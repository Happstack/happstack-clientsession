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
  , SessionConf(..)
  , mkSessionConf
  , ClientSessionT(..)
  , runClientSessionT
  , MonadClientSession(getSession, putSession, expireSession)
  , viewStateT'
  , StateT'
  , sessionPart
  , withClientSessionT
  ) where

import Control.Applicative   (Applicative, Alternative, optional)
import Control.Monad         (MonadPlus)
import Control.Monad.Error   (MonadError)
import Control.Monad.Fix     (MonadFix)
import Control.Monad.Reader  (MonadReader(ask, local))
import Control.Monad.State   (MonadState(get,put), StateT(..), modify, gets)
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

data ChangeStatus
    = Unread | Decoded | Modified  | Expired | NoChange
      deriving (Eq, Ord, Read, Show)

instance Monoid ChangeStatus where
    mempty = NoChange
    Unread   `mappend` NoChange = Unread
    Unread   `mappend` cs       = cs
    Decoded  `mappend` Modified = Modified
    Decoded  `mappend` Expired  = Expired
    Decoded  `mappend` NoChange = Decoded
    Decoded  `mappend` Decoded  = Decoded
    Decoded  `mappend` Unread   = error "how did this happen?"
    Modified `mappend` Expired  = Expired
    Modified `mappend` _        = Modified
    Expired  `mappend` Modified = Modified
    Expired  `mappend` _        = Expired
    NoChange `mappend` cs       = cs


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

-- | StateT' (which needs a better name), is like StateT, except it records if 'put' was ever called
newtype StateT' s m a = StateT' { unStateT' :: StateT (ChangeStatus, s) m a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadPlus, MonadIO, MonadFix, MonadError e, MonadCont
             , HasRqData, FilterMonad r, WebMonad r, ServerMonad)

instance Happstack m => Happstack (StateT' sessionData m)

instance MonadTrans (StateT' sessionData) where
    lift = StateT' . lift

instance (Monad m) => MonadState st (StateT' st m)  where
    get   = StateT' (gets snd)
    put a = StateT' $ put (Modified, a)

newtype ClientSessionT sessionData m a = ClientSessionT { unClientSessionT :: RWST SessionConf () (ChangeStatus, sessionData) m a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadPlus, MonadIO, MonadFix, MonadError e, MonadCont
             , HasRqData, FilterMonad r, WebMonad r, ServerMonad)

runClientSessionT :: (Functor m, Monad m, ClientSession sessionData) => ClientSessionT sessionData m a -> SessionConf -> m (a, ChangeStatus, sessionData)
runClientSessionT cs sc =
    do (a, (changeStatus, sessionData), ()) <- runRWST (unClientSessionT cs) sc (Unread, emptySession)
       return (a, changeStatus, sessionData)

instance Happstack m => Happstack (ClientSessionT sessionData m)

instance MonadTrans (ClientSessionT sessionData) where
    lift = ClientSessionT . lift

instance (MonadReader r m) => MonadReader r (ClientSessionT sessionData m) where
    ask = lift ask
    local f (ClientSessionT rwst) = ClientSessionT (mapRWST (local f) rwst)

instance (MonadWriter w m) => MonadWriter w (ClientSessionT sessionData m) where
    tell     = lift . tell
    listen (ClientSessionT rwst) = ClientSessionT $ mapRWST listen' rwst
        where
          listen' m =
              do ((a, s, w),w') <- listen m
                 return ((a, w'), s, w)
    pass (ClientSessionT rwst) = ClientSessionT $ mapRWST pass' rwst
        where
          pass' m =
              do ((a, f), st, w) <- m
                 a' <- pass $ return (a, f)
                 return (a', st, w)

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

setChangeStatus :: (Monad m) => ChangeStatus -> ClientSessionT sessionData m ()
setChangeStatus cs = ClientSessionT $ modify (\(_, sd) -> (cs, sd))

getChangeStatus :: (Monad m) => ClientSessionT sessionData m ChangeStatus
getChangeStatus = ClientSessionT $ gets fst


-- | Fetch the current value of the state within the monad.
getSessionData :: (Monad m) => ClientSessionT sessionData m sessionData
getSessionData = ClientSessionT $ gets snd

-- | @'put' s@ sets the state within the monad to @s@.
putSessionData :: (Monad m) => sessionData -> ClientSessionT sessionData m ()
putSessionData sd = ClientSessionT $ put (Modified, sd)

getSessionCST :: (Functor m, MonadPlus m, HasRqData m, ClientSession st)
           => ClientSessionT st m st
getSessionCST =
    do cs <- getChangeStatus
       case cs of
         Unread ->
             do a <- getValue
                ClientSessionT $ put (Decoded, a)
                return a
         Decoded  ->
             do getSessionData
         Modified ->
             do getSessionData
         Expired ->
             do newSession
         NoChange ->
             do getSessionData

getValue :: (Functor m, Monad m, MonadPlus m, HasRqData m, ClientSession sessionData) =>
            ClientSessionT sessionData m sessionData
getValue = do name <- asksSessionConf sessionCookieName
              value <- optional $ lookCookieValue name
              maybe newSession decode value

decode :: (Monad m, ClientSession b) =>
          String
       -> ClientSessionT sessionData m b
decode v = do key <- asksSessionConf sessionKey
              maybe newSession (either (const newSession) return . runGet safeGet)
                     . decrypt key $ pack v

newSession :: (Monad m, ClientSession st) => m st
newSession = return emptySession

-- | Put a new value in the session.
putSessionCST :: (Monad m, ClientSession sessionData) => sessionData -> ClientSessionT sessionData m ()
putSessionCST sd = putSessionData sd

-- | Expire the session, i.e. the cookie holding it.
expireSessionCST :: Monad m => ClientSessionT st m ()
expireSessionCST = setChangeStatus Expired

class MonadClientSession sessionData m | m -> sessionData where
    getSession    :: m sessionData
    putSession    :: sessionData -> m ()
    expireSession :: m ()

instance (Functor m , MonadPlus m, HasRqData m, ClientSession sessionData) =>
    (MonadClientSession sessionData (ClientSessionT sessionData m)) where
    getSession    = getSessionCST
    putSession    = putSessionCST
    expireSession = expireSessionCST

-- | Run a 'StateT'' monad with the session.
--
-- This is provided so that you can use the functions from 'Data.Lens'
-- which rely on 'MonadState'
viewStateT' :: (Monad (t m), Monad m, MonadTrans t, MonadClientSession sessionData (t m)) =>
               StateT' sessionData m b
            -> t m b
viewStateT' m =
    do sd <- getSession
       (a, (cs, sd')) <- lift $ runStateT (unStateT' m) (NoChange, sd)
       case cs of
         Modified -> putSession sd'
         Decoded  -> return ()
         NoChange -> return ()
         Unread   -> return ()
         Expired  -> error "viewStateT': the impossible happened"
       return a

-- | Wrapper around your handlers that use the session.  Takes care of
-- expiring the cookie of an expired session, or encrypting a modified
-- session into the cookie.
sessionPart :: (Functor m, Monad m, MonadIO m, FilterMonad Response m, ClientSession st)
            => ClientSessionT st m a -> ClientSessionT st m a
sessionPart part = do
    a  <- part
    cs <- getChangeStatus
    case cs of
      Modified    -> encode
      Expired     -> expire
      _           -> return ()
    return a
  where
    encode = do SessionConf{..} <- askSessionConf
                sd <- getSessionData
                bytes <- liftIO . encryptIO sessionKey . runPut . safePut $ sd
                addCookie sessionCookieLife $ (mkCookie sessionCookieName $ unpack bytes) { secure = sessionSecure }
    expire = do name <- asksSessionConf sessionCookieName
                expireCookie name

-- | Wrapper around your handlers that use the session.  Takes care of
-- expiring the cookie of an expired session, or encrypting a modified
-- session into the cookie.
withClientSessionT :: (Happstack m, Functor m, Monad m, MonadIO m, FilterMonad Response m, ClientSession sessionData, Show sessionData)
            => SessionConf -> ClientSessionT sessionData m a -> m a
withClientSessionT sessionConf@SessionConf{..} part = do
  do (a, cs, sd) <- runClientSessionT part sessionConf
     case cs of
      Modified    -> encode sd
      Expired     -> expire
      _           -> return ()
     return a
  where
    encode sd = do bytes <- liftIO . encryptIO sessionKey . runPut . safePut $ sd
                   addCookie sessionCookieLife $ (mkCookie sessionCookieName $ unpack bytes) { secure = sessionSecure }
    expire = do expireCookie sessionCookieName
