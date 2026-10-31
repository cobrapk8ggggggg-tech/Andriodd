import Foundation
import CryptoKit

/// Compatible with zeus_android.sealed. No credential is placed in a URL or log.
enum ZeusLabEnvelope {
    struct Box: Codable {
        let version: Int
        let session: String
        let ephemeral_public_key: String
        let nonce: String
        let ciphertext: String
    }
    static func context(_ session:UUID)->Data { Data(session.uuidString.lowercased().utf8) }
    static func key(_ secret:SharedSecret,session:UUID)->SymmetricKey {
        secret.hkdfDerivedSymmetricKey(using:SHA256.self,salt:context(session),sharedInfo:Data("ZEUS Android Lab envelope v1".utf8),outputByteCount:32)
    }
    static func seal(_ data:Data,to publicKey:String,session:UUID)throws->Box {
        guard data.count<=4*1024*1024,let raw=Data(base64Encoded:publicKey),raw.count==32 else { throw failure("حجم رسالة المختبر أو مفتاحها غير صالح") }
        let ephemeral=Curve25519.KeyAgreement.PrivateKey(),recipient=try Curve25519.KeyAgreement.PublicKey(rawRepresentation:raw)
        let shared=try ephemeral.sharedSecretFromKeyAgreement(with:recipient)
        let sealed=try AES.GCM.seal(data,using:key(shared,session:session),authenticating:Data("zeus-lab.v1:".utf8)+context(session))
        return Box(version:1,session:session.uuidString.lowercased(),ephemeral_public_key:ephemeral.publicKey.rawRepresentation.base64EncodedString(),nonce:Data(sealed.nonce).base64EncodedString(),ciphertext:(sealed.ciphertext+sealed.tag).base64EncodedString())
    }
    static func open(_ box:Box,using privateKey:Data,session:UUID)throws->Data {
        guard box.version==1,UUID(uuidString:box.session)==session,
              let publicData=Data(base64Encoded:box.ephemeral_public_key),publicData.count==32,
              let nonce=Data(base64Encoded:box.nonce),nonce.count==12,
              let ciphertext=Data(base64Encoded:box.ciphertext),ciphertext.count>=16,ciphertext.count<=4*1024*1024 else { throw failure("مغلف المختبر لا يطابق الجلسة أو يتجاوز الحد") }
        let recipient=try Curve25519.KeyAgreement.PrivateKey(rawRepresentation:privateKey)
        let sender=try Curve25519.KeyAgreement.PublicKey(rawRepresentation:publicData)
        let shared=try recipient.sharedSecretFromKeyAgreement(with:sender)
        let sealed=try AES.GCM.SealedBox(combined:nonce+ciphertext)
        return try AES.GCM.open(sealed,using:key(shared,session:session),authenticating:Data("zeus-lab.v1:".utf8)+context(session))
    }
    private static func failure(_ message:String)->NSError { NSError(domain:"ZEUSLabEnvelope",code:1,userInfo:[NSLocalizedDescriptionKey:message]) }
}
