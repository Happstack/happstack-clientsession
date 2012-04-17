{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE RecordWildCards #-}

module Happstack.Server.ClientSession
  ( ClientSession(..)
  , SessionConf(..)
  , mkSessionConf
  , ClientSessionT
  , runClientSessionT
  , getSession
  , putSession
  , expireSession
  , withSession
  , sessionPart
  ) where

import Control.Applicative   (Applicative, Alternative, optional)
import Control.Monad         (MonadPlus, when)
import Control.Monad.Reader  (ReaderT, runReaderT, ask, asks)
import Control.Monad.State   (StateT, State, evalStateT, runState, get, put)
import Control.Monad.Trans   (MonadIO, liftIO)
import Data.ByteString.Char8 (pack, unpack)
import Data.SafeCopy         (SafeCopy, safeGet, safePut)
import Data.Serialize        (runGet, runPut)
import Happstack.Server      (HasRqData, FilterMonad, WebMonad, ServerMonad, Happstack, Response, CookieLife(Session), Cookie(secure), lookCookieValue, addCookie, mkCookie, expireCookie)
import Web.ClientSession     (Key, decrypt, encryptIO)

-- | Your session type must have an instance for this class.
class SafeCopy st => ClientSession st where
  -- | An empty session, i.e. what you get when there is no existing
  -- session stored.
  empty :: st

data SessionState st = Encoded | Decoded st | Modified st | Expired

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
    , sessionSecure     = True
    }

-- | Transformer for monads capable of using a session.
newtype ClientSessionT st m a =
    ClientSessionT { unClientSessionT :: ReaderT SessionConf (StateT (SessionState st) m) a }
  deriving ( Functor, Applicative, Alternative
           , Monad, MonadIO, MonadPlus
           , HasRqData, FilterMonad r, WebMonad r, ServerMonad
           )

instance Happstack m => Happstack (ClientSessionT st m)

-- | Get the inner monad of a 'ClientSessionT'.
runClientSessionT :: Monad m => ClientSessionT st m a -> SessionConf -> m a
runClientSessionT cs sc =
    evalStateT (runReaderT (unClientSessionT cs) sc) Encoded

askCS :: Monad m => ClientSessionT st m SessionConf
askCS = ClientSessionT ask

asksCS :: Monad m => (SessionConf -> a) -> ClientSessionT st m a
asksCS = ClientSessionT . asks

getCS :: Monad m => ClientSessionT st m (SessionState st)
getCS = ClientSessionT get

putCS :: Monad m => SessionState st -> ClientSessionT st m ()
putCS = ClientSessionT . put

-- | Get the session value.  If the cookie has not been decoded yet, it
-- will be decoded.  If no session data is stored or the session has been
-- expired, 'empty' is returned.
getSession :: (Functor m, MonadPlus m, HasRqData m, ClientSession st)
           => ClientSessionT st m st
getSession = do
    ss <- getCS
    case ss of
      Decoded a  -> return a
      Modified a -> return a
      Expired    -> new
      Encoded    -> do a <- getValue
                       putCS $ Decoded a
                       return a
  where
    new      = return empty
    getValue = do name <- asksCS sessionCookieName
                  value <- optional $ lookCookieValue name
                  maybe new decode value
    decode v = do key <- asksCS sessionKey
                  maybe new (either (const new) return . runGet safeGet)
                    . decrypt key $ pack v

-- | Put a new value in the session.
putSession :: (Monad m, ClientSession st) => st -> ClientSessionT st m ()
putSession = putCS . Modified

-- | Expire the session, i.e. the cookie holding it.
expireSession :: Monad m => ClientSessionT st m ()
expireSession = putCS Expired

-- | Run a 'State' monad with the session.
withSession :: (Functor m, MonadPlus m, HasRqData m, ClientSession st, Eq st)
            => State st a -> ClientSessionT st m a
withSession m = do s <- getSession
                   let (a,st) = runState m s
                   when (st /= s) $ putSession st
                   return a

-- | Wrapper around your handlers that use the session.  Takes care of
-- expiring the cookie of an expired session, or encrypting a modified
-- session into the cookie.
sessionPart :: (Functor m, Monad m, MonadIO m, FilterMonad Response m, ClientSession st)
            => ClientSessionT st m a -> ClientSessionT st m a
sessionPart part = do
    a  <- part
    ss <- getCS
    case ss of
      Modified st -> encode st
      Expired     -> expire
      _           -> return ()
    return a
  where
    encode st = do SessionConf{..} <- askCS
                   bytes <- liftIO . encryptIO sessionKey . runPut . safePut $ st
                   addCookie sessionCookieLife $ (mkCookie sessionCookieName $ unpack bytes) { secure = sessionSecure }
    expire    = do name <- asksCS sessionCookieName
                   expireCookie name
