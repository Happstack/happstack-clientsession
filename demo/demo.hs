{-# LANGUAGE DeriveDataTypeable, GeneralizedNewtypeDeriving, TemplateHaskell, OverloadedStrings #-}
module Main where

import Control.Applicative
import Control.Monad (MonadPlus, msum)
import Control.Monad.Trans (MonadIO(liftIO), MonadTrans(lift))
import Happstack.Server
import Happstack.Server.ClientSession
import Data.Data
import Data.Lens           ((+=))
import Data.Lens.Template
import Data.SafeCopy
import Data.Text
import           Text.Blaze ((!))
import qualified Text.Blaze.Html4.Strict as H
import qualified Text.Blaze.Html4.Strict.Attributes as A
import Web.ClientSession (getDefaultKey)

data SessionData = SessionData
    { _count    :: Integer
    }
    deriving (Eq, Ord, Read, Show, Data, Typeable)

$(makeLens ''SessionData)
$(deriveSafeCopy 0 'base ''SessionData)

instance ClientSession SessionData where
    emptySession =
        SessionData { _count    = 0
                    }

newtype AppT m a = AppT { runApp :: ClientSessionT SessionData (ServerPartT m) a }
    deriving (Functor, Applicative, Alternative, Monad, MonadIO, MonadPlus, MonadClientSession SessionData,
              FilterMonad Response, WebMonad Response, ServerMonad, HasRqData, Happstack)

instance MonadTrans AppT where
    lift = AppT . lift . lift

type App = AppT IO

appTemplate :: String -> [H.Html] -> H.Html -> H.Html
appTemplate title headers body =
    H.html $ do
      H.head $ do
        H.title (H.toHtml title)
        H.meta ! A.httpEquiv "Content-Type" ! A.content "text/html;charset=utf-8"
        sequence_ headers
      H.body $ do
        body

routes :: App Response
routes =
    do nullDir
       c <- liftSessionStateT $ count += 1
       ok $ toResponse $
          appTemplate "Viewing Session Data" [] $
                      H.p $ do H.toHtml c

main :: IO ()
main =
    do key <- getDefaultKey
       let sessionConf = mkSessionConf key
       simpleHTTP nullConf $ withClientSessionT sessionConf $ runApp routes
