{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
{- |

This module provides a simple session implementation which stores session data on the client as a cookie value.

The cookie values stored in an encryted cookie to make it more difficult for users to tamper with the values. However, this does not prevent replay attacks, and should not be seen as a substitute for using HTTPS.


-}

module Happstack.Server.ClientSession
  ( ClientSession(..)
  , MonadClientSession(getSession, putSession, expireSession)
  , SessionConf(..)
  , mkSessionConf
  , ClientSessionT(..)
  , runClientSessionT
  , withClientSessionT
  , SessionStateT
  , liftSessionStateT
  ) where

import Control.Applicative   (Applicative, Alternative, optional)
import Control.Monad         (MonadPlus)
import Control.Monad.Error   (MonadError)
import Control.Monad.Fix     (MonadFix)
import Control.Monad.Reader  (MonadReader(ask, local), ReaderT(..), mapReaderT)
import Control.Monad.State   (MonadState(get,put), StateT(..), mapStateT, modify, gets)
import Control.Monad.Writer  (MonadWriter(tell, listen, pass))
import Control.Monad.RWS     (MonadRWS, RWST(..), mapRWST, runRWST)
import Control.Monad.Trans   (MonadIO(liftIO), MonadTrans(lift))
import Control.Monad.Cont    (MonadCont)
import Data.ByteString.Char8 (pack, unpack)
import Data.Monoid           (Monoid(..))
import Data.SafeCopy         (SafeCopy, safeGet, safePut)
import Data.Serialize        (runGet, runPut)
import Happstack.Server      (HasRqData, FilterMonad, WebMonad, ServerMonad, Happstack, Response, CookieLife(Session), Cookie(secure), lookCookieValue, addCookie, mkCookie, expireCookie)
import Web.ClientSession     (Key, decrypt, encryptIO)

-- | Your session type must have an instance for this class.
class SafeCopy st => ClientSession st where
  -- | An empty session, i.e. what you get when there is no existing
  -- session stored.
  emptySession :: st

data SessionData sessionData = Unread | NoChange sessionData | Modified sessionData  | Expired
      deriving (Eq, Ord, Read, Show)

-- | Configuration for the session cookie for passing to 'runClientSessionT'.
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
-- >           simpleHTTP nullConf $ runClientSessionT handlers sessConf
-- >   where
-- >     oneWeek  = MaxAge $ 60 * 60 * 24 * 7
-- >     handlers = sessionPart $ msum [...]
mkSessionConf :: Key -> SessionConf
mkSessionConf key = SessionConf
    { sessionCookieName = "Happstack.ClientSession"
    , sessionCookieLife = Session
    , sessionKey        = key
    , sessionSecure     = False
    }

-- | SessionStateT (which needs a better name), is like StateT, except it records if 'put' was ever called
newtype SessionStateT s m a = SessionStateT { unSessionStateT :: StateT (SessionData s) m a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadPlus, MonadIO, MonadFix, MonadError e, MonadCont
             , HasRqData, FilterMonad r, WebMonad r, ServerMonad)

mapSessionStateT :: (m (a, SessionData s) -> n (b, SessionData s)) -> SessionStateT s m a -> SessionStateT s n b
mapSessionStateT f (SessionStateT m) = SessionStateT $ mapStateT f m

instance Happstack m => Happstack (SessionStateT sessionData m)

instance MonadTrans (SessionStateT sessionData) where
    lift = SessionStateT . lift

instance (Monad m, ClientSession sessionData) => MonadState sessionData (SessionStateT sessionData m)  where
    get   = SessionStateT $ do sd <- get
                               case sd of
                                 (NoChange  sd') -> return sd'
                                 (Modified sd') -> return sd'
                                 _              -> return emptySession
    put a = SessionStateT $ put (Modified a)

runSessionStateT :: SessionStateT sessionData m a -> SessionData sessionData -> m (a, SessionData sessionData)
runSessionStateT m sd = runStateT (unSessionStateT m) sd

newtype ClientSessionT sessionData m a = ClientSessionT { unClientSessionT :: ReaderT SessionConf (SessionStateT sessionData m) a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadPlus, MonadIO, MonadFix, MonadError e, MonadCont
             , HasRqData, FilterMonad r, WebMonad r, ServerMonad)

runClientSessionT :: ClientSessionT sessionData m a -> SessionConf -> m (a, SessionData sessionData)
runClientSessionT cs sc = runSessionStateT (runReaderT (unClientSessionT cs) sc) Unread

instance Happstack m => Happstack (ClientSessionT sessionData m)

instance MonadTrans (ClientSessionT sessionData) where
    lift = ClientSessionT . lift . lift

mapClientSessionT :: (m (a, SessionData sessionData) -> n (b, SessionData sessionData))
                  -> ClientSessionT sessionData m a
                  -> ClientSessionT sessionData n b
mapClientSessionT f (ClientSessionT m) = ClientSessionT $ mapReaderT (mapSessionStateT f) m

instance (MonadReader r m) => MonadReader r (ClientSessionT sessionData m) where
    ask = lift ask
    local f m = mapClientSessionT (local f) m

instance (MonadWriter w m) => MonadWriter w (ClientSessionT sessionData m) where
    tell     = lift . tell

    listen m = mapClientSessionT listen' m
        where
          listen' m =
              do ((a, s), w') <- listen m
                 return ((a, w'), s)
    pass m = mapClientSessionT pass' m
        where
          pass' m =
              do ((a, f), st) <- m
                 a' <- pass $ return (a, f)
                 return (a', st)

instance (MonadState s m) => MonadState s (ClientSessionT sessionData m) where
    get   = lift get
    put a = lift (put a)

instance (MonadRWS r w s m) => MonadRWS r w s (ClientSessionT sessionData m)

-- | Fetch the 'SessionConf'
askSessionConf :: (Monad m) => ClientSessionT sessionData m SessionConf
askSessionConf = ClientSessionT $ ask

asksSessionConf :: (Monad m) => (SessionConf -> a) -> ClientSessionT sessionData m a
asksSessionConf f = do
    sc <- askSessionConf
    return (f sc)

-- | Fetch the current value of the state within the monad.
getSessionData :: (Monad m) => ClientSessionT sessionData m (SessionData sessionData)
getSessionData =
    ClientSessionT $ ReaderT $ \_ -> SessionStateT $ get

-- | @'put' s@ sets the state within the monad to @s@.
putSessionData :: (Monad m) => (SessionData sessionData) -> ClientSessionT sessionData m ()
putSessionData sd =
    ClientSessionT $ ReaderT $ \_ -> SessionStateT $ put sd

newSession :: (Monad m, ClientSession st) => m st
newSession = return emptySession

decode :: (Monad m, ClientSession b) =>
          String
       -> ClientSessionT sessionData m b
decode v = do key <- asksSessionConf sessionKey
              maybe newSession (either (const newSession) return . runGet safeGet)
                     . decrypt key $ pack v


getValue :: (Functor m, Monad m, MonadPlus m, HasRqData m, ClientSession sessionData) =>
            ClientSessionT sessionData m sessionData
getValue = do name <- asksSessionConf sessionCookieName
              value <- optional $ lookCookieValue name
              maybe newSession decode value

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
             do return a
         Modified a ->
             do return a
         Expired ->
             do newSession

-- | Put a new value in the session.
putSessionCST :: (Monad m, ClientSession sessionData) => sessionData -> ClientSessionT sessionData m ()
putSessionCST sd = putSessionData (Modified sd)

-- | Expire the session, i.e. the cookie holding it.
expireSessionCST :: Monad m => ClientSessionT st m ()
expireSessionCST = putSessionData Expired

class MonadClientSession sessionData m | m -> sessionData where
    getSession    :: m sessionData
    putSession    :: sessionData -> m ()
    expireSession :: m ()

instance (Functor m , MonadPlus m, HasRqData m, ClientSession sessionData) =>
    (MonadClientSession sessionData (ClientSessionT sessionData m)) where
    getSession    = getSessionCST
    putSession    = putSessionCST
    expireSession = expireSessionCST

-- | Run a 'SessionStateT' monad with the session.
--
-- This is provided so that you can use the functions from 'Data.Lens'
-- which rely on 'MonadState'
-- liftSessionStateT :: (Monad (t m), Monad m, MonadTrans t, MonadClientSession sessionData (t m)) =>
--               SessionStateT sessionData m b
--            -> t m b
liftSessionStateT :: (Monad m, MonadTrans t, MonadClientSession sessionData (t m), Monad (t m)) => SessionStateT sessionData m a -> t m a
liftSessionStateT m =
    do sd <- getSession
       (a, sd') <- lift $ runSessionStateT m (NoChange sd)
       case sd' of
         (Modified sd'') -> putSession sd''
         (NoChange  _   ) -> return ()
         Unread          -> error $ "liftSessionStateT: session data came back Unread. How did that happen?"
         Expired         -> error $ "liftSessionStateT: session data came back Expired. How did that happen?"
       return a

-- | Wrapper around your handlers that use the session.  Takes care of
-- expiring the cookie of an expired session, or encrypting a modified
-- session into the cookie.
withClientSessionT :: (Happstack m, Functor m, Monad m, FilterMonad Response m, ClientSession sessionData) =>
                      SessionConf
                   -> ClientSessionT sessionData m a
                   -> m a
withClientSessionT sessionConf@SessionConf{..} part = do
  do (a, sd) <- runClientSessionT part sessionConf
     case sd of
      Modified sd' -> encode sd'
      Expired      -> expire
      _            -> return ()
     return a
  where
    encode sd = do bytes <- liftIO . encryptIO sessionKey . runPut . safePut $ sd
                   addCookie sessionCookieLife $ (mkCookie sessionCookieName $ unpack bytes) { secure = sessionSecure }
    expire = do expireCookie sessionCookieName
