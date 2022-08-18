package com.koch

import com.ncipher.nfast.marshall.*
import com.ncipher.provider.Conversions
import com.ncipher.provider.CoreECKey
import com.ncipher.provider.Utils


/**
 *
 * Sample usage:
 *
 * NCipherPreHashSignProvider.sign(Supplier.getInstance().privateKey as CoreECKey, MyBenchmark().inputHash)
 *
 * possible algorithm values:
 * - ECDSAhSHA256
 * - ECDSAhSHA384
 * - ECDSAhSHA512
 */
class NCipherPreHashSignProvider {

    companion object {
        fun sign(privateKey: CoreECKey, message: ByteArray, algorithm: String = "ECDSAhSHA256"): ByteArray {
            val command = M_Command()
            val args = M_Cmd_Args_Sign()
            command.cmd = 55L
            command.args = args
            args.flags = 0L
            args.key = privateKey.keyID
            args.mech = M_Mech.toInt(algorithm).toLong()
            args.plain = Conversions.toPlainText(message, 93L)
            val reply = Utils.transact(command, true)
            val res = reply.reply as M_Cmd_Reply_Sign
            return Conversions.fromCipherText(res.sig, 185L, null)
        }
    }

}

/**
 * val prehashAndSignatureResult = NCipherPreHashSignProvider.sign(Supplier.getInstance().privateKey as CoreECKey, MyBenchmark().inputHash)
 *
 * val signatureVerify = Signature.getInstance(BCBenchmarker().hashSignatureAlgorithm, BCBenchmarker().provider)
 * signatureVerify.initVerify(Supplier.getInstance().publicKey)
 * signatureVerify.update(MyBenchmark().input)
 * println("sign (verify BC) = ${signatureVerify.verify(prehashAndSignatureResult)}")
 */