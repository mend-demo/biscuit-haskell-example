{-# LANGUAGE DataKinds         #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeFamilies      #-}
module Biscuit
  ( authHandler
  , RequireBiscuit
  , checkBiscuit
  , genBiscuitCtx
  ) where

import           Auth.Biscuit                     (Biscuit, PublicKey,
                                                   VerificationError, Verifier,
                                                   checkBiscuitSignature,
                                                   parseB64, verifyBiscuit)
import           Auth.Biscuit.Datalog.AST         (Query)
import           Control.Monad.Except             (throwError)
import           Control.Monad.IO.Class           (liftIO)
import           Data.Bifunctor                   (first)
import qualified Data.ByteString                  as BS
import qualified Data.ByteString.Char8            as C8
import qualified Data.ByteString.Lazy             as LBS
import           Data.Text                        (Text)
import           Network.Wai
import           Servant                          (AuthProtect)
import           Servant.Server
import           Servant.Server.Experimental.Auth

type RequireBiscuit = AuthProtect "biscuit"
type instance AuthServerData RequireBiscuit = CheckedBiscuit

data CheckedBiscuit = CheckedBiscuit PublicKey Biscuit

extractBiscuit :: Request -> Either String Biscuit
extractBiscuit req = do
  let note e = maybe (Left e) Right
  authHeader <- note "Missing Authorization header" . lookup "Authorization" $ requestHeaders req
  b64Token   <- note "Not a Bearer token" $ BS.stripPrefix "Bearer " authHeader
  first (const "Not a B64-encoded biscuit") $ parseB64 b64Token

authHandler :: PublicKey -> AuthHandler Request CheckedBiscuit
authHandler publicKey = mkAuthHandler handler
  where
    authError s = err401 { errBody = LBS.fromStrict (C8.pack s) }
    orError = either (throwError . authError) pure
    handler req = do
      biscuit <- orError $ extractBiscuit req
      result  <- liftIO $ checkBiscuitSignature biscuit publicKey
      case result of
        False -> throwError $ authError "Invalid signature"
        True  -> pure $ CheckedBiscuit publicKey biscuit

genBiscuitCtx :: PublicKey -> Context '[AuthHandler Request CheckedBiscuit]
genBiscuitCtx pk = authHandler pk :. EmptyContext

checkBiscuit :: CheckedBiscuit
             -> Verifier
             -> Handler a
             -> Handler a
checkBiscuit (CheckedBiscuit pk b) v h = do
  res <- liftIO $ verifyBiscuit b v pk
  case res of
    Left e  -> throwError $ err401 { errBody = "Biscuit failed checks" }
    Right _ -> h
