{-# LANGUAGE DeriveDataTypeable, FlexibleContexts, FlexibleInstances, FunctionalDependencies, GeneralizedNewtypeDeriving, MultiParamTypeClasses, RecordWildCards, Rank2Types, ScopedTypeVariables, TypeFamilies, UndecidableInstances #-}
{- |

This module provides a simple session implementation which stores session data on the client as a cookie value.

The cookie values stored in an encryted cookie to make it more difficult for users to tamper with the values. However, this does not prevent replay attacks, and should not be seen as a substitute for using HTTPS.


-}
module Happstack.Server.ClientSession
  ( ClientSession(..)
  , SessionData(..)
  , MonadClientSession(getSession, putSession, expireSession)
  , SessionConf(..)
  , mkSessionConf
  , ClientSessionT(..)
  , mapClientSessionT
  , runClientSessionT
  , withClientSessionT
  , SessionStateT
  , mapSessionStateT
  , liftSessionStateT
    -- * Exported from @Web.ClientSession@
  , Key
  , getKey
  , getDefaultKey
  ) where

import Control.Applicative   (Applicative, Alternative, optional)
import Control.Monad         (MonadPlus(..), liftM)
import Control.Monad.Base    (MonadBase )
import Control.Monad.Cont    (MonadCont)
import Control.Monad.Error   (MonadError)
import Control.Monad.Fix     (MonadFix)
import Control.Monad.Reader  (MonadReader(ask, local), ReaderT(..), mapReaderT)
import Control.Monad.State   (MonadState(get,put), StateT(..), mapStateT)
import Control.Monad.Writer  (MonadWriter(tell, listen, pass))
import Control.Monad.RWS     (MonadRWS)
import Control.Monad.Trans   (MonadIO(liftIO), MonadTrans(lift))
import Control.Monad.Trans.Control               ( MonadTransControl(..)
                                                 , MonadBaseControl(..)
                                                 , ComposeSt, defaultLiftBaseWith, defaultRestoreM
                                                 )
import Data.ByteString.Char8 (pack, unpack)
import Data.Monoid           (Monoid(..))
import Data.SafeCopy         (SafeCopy, safeGet, safePut)
import Data.Serialize        (runGet, runPut)
import Happstack.Server      (HasRqData, FilterMonad, WebMonad, ServerMonad, Happstack, Response, CookieLife(Session), Cookie(secure), lookCookieValue, addCookie, mkCookie, expireCookie)
import Web.ClientSession     (Key, getKey, getDefaultKey, decrypt, encryptIO)

------------------------------------------------------------------------------
-- class ClientSession
------------------------------------------------------------------------------

-- | Your session type must have an instance for this class.
class SafeCopy st => ClientSession st where
  -- | An empty session, i.e. what you get when there is no existing
  -- session stored.
  emptySession :: st

------------------------------------------------------------------------------
-- SessionConf
------------------------------------------------------------------------------

-- | Configuration for the session cookie for passing to 'runClientSessionT' or 'withClientSessionT'.
data SessionConf = SessionConf
    { sessionCookieName :: String      -- ^ Name of the cookie to hold your session data.
    , sessionCookieLife :: CookieLife  -- ^ Lifetime of that cookie.
    , sessionKey        :: Key         -- ^ Encryption key, usually from 'getKey' or 'getDefaultKey'.
    , sessionSecure     :: Bool        -- ^ Only use a session over secure transports.
    }

-- | Create a 'SessionConf' using defaults for everything except
-- 'sessionKey'.  You can use record update syntax to override individual
-- fields.
--
-- > main = do key <- getDefaultKey
-- >           let sessConf = (mkSessionConf key) { sessionCookieLife = oneWeek }
-- >           simpleHTTP nullConf $ withClientSessionT sessConf handlers
-- >   where
-- >     oneWeek  = MaxAge $ 60 * 60 * 24 * 7
-- >     handlers = msum [...]
--
-- 'mkSessionConf' is currently defined as:
--
-- > mkSessionConf :: Key -> SessionConf
-- > mkSessionConf key = SessionConf
-- >    { sessionCookieName = "Happstack.ClientSession"
-- >    , sessionCookieLife = Session
-- >    , sessionKey        = key
-- >    , sessionSecure     = False
-- >    }
mkSessionConf :: Key -> SessionConf
mkSessionConf key = SessionConf
    { sessionCookieName = "Happstack.ClientSession"
    , sessionCookieLife = Session
    , sessionKey        = key
    , sessionSecure     = False
    }

------------------------------------------------------------------------------
-- SessionStateT
------------------------------------------------------------------------------

-- | Wrapper around the sessionData which tracks it state so we can
-- avoid decoding or encoding/sending the cookie when not required
data SessionData sessionData = Unread | NoChange sessionData | Modified sessionData  | Expired
      deriving (Eq, Ord, Read, Show)

-- | 'SessionStateT' is like 'StateT', except it records if 'put' was ever called
newtype SessionStateT s m a = SessionStateT { unSessionStateT :: StateT (SessionData s) m a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadPlus, MonadBase b, MonadIO, MonadFix, MonadError e, MonadCont
             , MonadTrans, HasRqData, FilterMonad r, WebMonad r, ServerMonad)

instance Happstack m => Happstack (SessionStateT sessionData m)

instance (MonadPlus m) => Monoid (SessionStateT sessionData m a) where
    mempty  = mzero
    mappend = mplus

instance (Monad m, ClientSession sessionData) => MonadState sessionData (SessionStateT sessionData m)  where
    get   = SessionStateT $ do sd <- get
                               case sd of
                                 (NoChange sd') -> return sd'
                                 (Modified sd') -> return sd'
                                 _              -> return emptySession
    put a = SessionStateT $ put (Modified a)

instance MonadTransControl (SessionStateT s) where
    newtype StT (SessionStateT s) a = StSessionStateT { unStSessionStateT :: StT (StateT (SessionData s)) a }
    liftWith f =
        SessionStateT $ liftWith $ \runStateT' ->
            f $ liftM StSessionStateT . runStateT' . unSessionStateT
    restoreT = SessionStateT . restoreT . liftM unStSessionStateT

instance MonadBaseControl b m => MonadBaseControl b (SessionStateT s m) where
    newtype StM (SessionStateT s m) a = StMSessionStateT { unStMSessionStateT :: ComposeSt (SessionStateT s) m a }
    liftBaseWith = defaultLiftBaseWith StMSessionStateT
    restoreM     = defaultRestoreM     unStMSessionStateT

-- | run 'SessionStateT' and get the result, plus the final @SessionData sessionData@
runSessionStateT :: SessionStateT sessionData m a -> SessionData sessionData -> m (a, SessionData sessionData)
runSessionStateT = runStateT . unSessionStateT

-- | Transform the inner monad. (similar to 'mapStateT')
--
-- The @forall s.@ is to prevent you from modifying the session state.
--
-- In theory we want this function to have the type:
--
-- > mapSessionStateT :: (m a -> n b) -> SessionStateT s m a -> SessionStateT s n b
--
-- But that can not be done, so this is the next best thing.
--
mapSessionStateT :: (forall s. m (a, s) -> n (b, s))
                 -> SessionStateT sessionData m a
                 -> SessionStateT sessionData n b
mapSessionStateT f (SessionStateT m) =
    SessionStateT $ mapStateT f m

-- | similar to 'mapStateT'. This version allows modification of the session data
mapSessionStateT_ :: (m (a, SessionData s) -> n (b, SessionData s))
                 -> SessionStateT s m a
                 -> SessionStateT s n b
mapSessionStateT_ f (SessionStateT m) = SessionStateT $ mapStateT f m

------------------------------------------------------------------------------
-- ClientSessionT
------------------------------------------------------------------------------

-- | 'ClientSessionT' provides an environment in which we can access and update the client-side session state
--
-- The inner monad needs to provide an instance of 'Happstack' so that
-- the cookie value can be read and set. According 'ClientSessionT'
-- must appear outside 'ServerPartT' not inside it.
newtype ClientSessionT sessionData m a = ClientSessionT { unClientSessionT :: ReaderT SessionConf (SessionStateT sessionData m) a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadBase b, MonadPlus, MonadIO, MonadFix, MonadError e, MonadCont
             , HasRqData, FilterMonad r, WebMonad r, ServerMonad)

-- | run the 'ClientSessionT' monad and get the result plus the final @SessionData sessionData@
runClientSessionT :: ClientSessionT sessionData m a -> SessionConf -> m (a, SessionData sessionData)
runClientSessionT cs sc = runSessionStateT (runReaderT (unClientSessionT cs) sc) Unread

instance Happstack m => Happstack (ClientSessionT sessionData m)

instance (MonadPlus m) => Monoid (ClientSessionT sessionData m a) where
    mempty  = mzero
    mappend = mplus

instance MonadTrans (ClientSessionT sessionData) where
    lift = ClientSessionT . lift . lift

instance MonadTransControl (ClientSessionT s) where
    newtype StT (ClientSessionT s) a = StClientSessionT { unStClientSessionT :: StT (SessionStateT s) (StT (ReaderT SessionConf) a) }

    liftWith f =
        ClientSessionT $ liftWith $ \runSessionStateT' ->
            liftWith $ \runReaderT' ->
            f $ liftM StClientSessionT . runReaderT' . runSessionStateT' . unClientSessionT

    restoreT = ClientSessionT . restoreT . restoreT . liftM unStClientSessionT

instance MonadBaseControl b m => MonadBaseControl b (ClientSessionT s m) where
    newtype StM (ClientSessionT s m) a = StMClientSessionT { unStMClientSessionT :: ComposeSt (ClientSessionT s) m a }
    liftBaseWith = defaultLiftBaseWith StMClientSessionT
    restoreM     = defaultRestoreM     unStMClientSessionT

-- | transform the inner monad, but leave the session data alone.
mapClientSessionT :: (forall s. m (a, s) -> n (b, s))
                  -> ClientSessionT sessionData m a
                  -> ClientSessionT sessionData n b
mapClientSessionT f (ClientSessionT m) = ClientSessionT $ mapReaderT (mapSessionStateT f) m

-- | transform the inner monad
mapClientSessionT_ :: (m (a, SessionData sessionData) -> n (b, SessionData sessionData))
                  -> ClientSessionT sessionData m a
                  -> ClientSessionT sessionData n b
mapClientSessionT_ f (ClientSessionT m) = ClientSessionT $ mapReaderT (mapSessionStateT_ f) m

instance (MonadReader r m) => MonadReader r (ClientSessionT sessionData m) where
    ask = lift ask
    local = mapClientSessionT_ . local

instance (MonadWriter w m) => MonadWriter w (ClientSessionT sessionData m) where
    tell     = lift . tell

    listen = mapClientSessionT listen'
        where
          listen' m =
              do ((a, s), w') <- listen m
                 return ((a, w'), s)
    pass = mapClientSessionT pass'
        where
          pass' m =
              do ((a, f), st) <- m
                 a' <- pass $ return (a, f)
                 return (a', st)

instance (MonadState s m) => MonadState s (ClientSessionT sessionData m) where
    get   = lift get
    put a = lift (put a)

instance (MonadRWS r w s m) => MonadRWS r w s (ClientSessionT sessionData m)

------------------------------------------------------------------------------
-- Internals
------------------------------------------------------------------------------

-- | Fetch the 'SessionConf'
askSessionConf :: (Monad m) => ClientSessionT sessionData m SessionConf
askSessionConf = ClientSessionT ask

-- | Fetch the 'SessionConf' and apply a function to it
asksSessionConf :: (Monad m) => (SessionConf -> a) -> ClientSessionT sessionData m a
asksSessionConf f = do
    sc <- askSessionConf
    return (f sc)

-- | Fetch the current value of the state within the monad.
getSessionData :: (Monad m) => ClientSessionT sessionData m (SessionData sessionData)
getSessionData =
    ClientSessionT $ ReaderT $ \_ -> SessionStateT get

-- | @'put' s@ sets the state within the monad to @s@.
putSessionData :: Monad m => SessionData sessionData -> ClientSessionT sessionData m ()
putSessionData sd =
    ClientSessionT $ ReaderT $ \_ -> SessionStateT $ put sd

-- | create a new session by calling 'emptySession'
newSession :: (Monad m, ClientSession st) => m st
newSession = return emptySession

-- | decode the encypted cookie string
decode :: (Monad m, ClientSession sessionData) =>
          String
       -> ClientSessionT sessionData m sessionData
decode v = do key <- asksSessionConf sessionKey
              maybe newSession (either (const newSession) return . runGet safeGet)
                     . decrypt key $ pack v

-- | get the session cookie and decrypt it. If no cookie is found, return a new 'emptySession'.
getValue :: (Functor m, Monad m, MonadPlus m, HasRqData m, ClientSession sessionData) =>
            ClientSessionT sessionData m sessionData
getValue = do name <- asksSessionConf sessionCookieName
              value <- optional $ lookCookieValue name
              maybe newSession decode value

-- | get the @sessionData@
getSessionCST :: (Functor m, MonadPlus m, HasRqData m, ClientSession sessionData)
           => ClientSessionT sessionData m sessionData
getSessionCST =
    do sd <- getSessionData
       case sd of
         Unread ->
             do a <- getValue
                putSessionData (NoChange a)
                return a
         NoChange a  ->
             return a
         Modified a ->
             return a
         Expired ->
             newSession

-- | Put a new value in the session.
putSessionCST :: (Monad m, ClientSession sessionData) => sessionData -> ClientSessionT sessionData m ()
putSessionCST sd = putSessionData (Modified sd)

-- | Expire the session, i.e. the cookie holding it.
expireSessionCST :: Monad m => ClientSessionT st m ()
expireSessionCST = putSessionData Expired

------------------------------------------------------------------------------
-- MonadClientSession
------------------------------------------------------------------------------

-- | 'MonadClientSession' provides the primary interface to get @sessionData@, put @sessionData@ or expire @sessionData@.
--
-- This is a class so you can use newtype deriving to make the functions available in your custom server monad.
class MonadClientSession sessionData m | m -> sessionData where
    getSession    :: m sessionData         -- ^ get the current @sessionData@
    putSession    :: sessionData -> m ()   -- ^ set the @sessionData@
    expireSession :: m ()                  -- ^ expire the session (deletes the cookie)

instance (Functor m , MonadPlus m, HasRqData m, ClientSession sessionData) =>
    (MonadClientSession sessionData (ClientSessionT sessionData m)) where
    getSession    = getSessionCST
    putSession    = putSessionCST
    expireSession = expireSessionCST

------------------------------------------------------------------------------
-- liftSessionStateT
------------------------------------------------------------------------------

-- | lift a computation from the 'SessionStateT' monad
--
-- The primary purpose of this function is to make it possible to use
-- the 'MonadState' functions such as 'get' and 'set' to get and set
-- the current session data.
--
-- That makes it possible to use the 'MonadState' based functions provided by 'Data.Lens', e.g.:
--
-- > do c <- liftSessionStateT $ count += 1
--
liftSessionStateT :: (Monad m, MonadTrans t, MonadClientSession sessionData (t m), Monad (t m)) =>
                     SessionStateT sessionData m a
                  -> t m a
liftSessionStateT m =
    do sd <- getSession
       (a, sd') <- lift $ runSessionStateT m (NoChange sd)
       case sd' of
         (Modified sd'') -> putSession sd''
         (NoChange _   ) -> return ()
         Unread          -> error "liftSessionStateT: session data came back Unread. How did that happen?"
         Expired         -> error "liftSessionStateT: session data came back Expired. How did that happen?"
       return a

------------------------------------------------------------------------------
-- withClientSessionT
------------------------------------------------------------------------------

-- | Wrapper around your handlers that use the session.  Takes care of
-- expiring the cookie of an expired session, or encrypting a modified
-- session into the cookie.
withClientSessionT :: (Happstack m, Functor m, Monad m, FilterMonad Response m, ClientSession sessionData) =>
                      SessionConf
                   -> ClientSessionT sessionData m a
                   -> m a
withClientSessionT sessionConf@SessionConf{..} part =
  do (a, sd) <- runClientSessionT part sessionConf
     case sd of
      Modified sd' -> encode sd'
      Expired      -> expire
      _            -> return ()
     return a
  where
    encode sd = do bytes <- liftIO . encryptIO sessionKey . runPut . safePut $ sd
                   addCookie sessionCookieLife $ (mkCookie sessionCookieName $ unpack bytes) { secure = sessionSecure }
    expire = expireCookie sessionCookieName
