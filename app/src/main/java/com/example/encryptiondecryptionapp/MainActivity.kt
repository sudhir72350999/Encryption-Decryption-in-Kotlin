package com.example.encryptiondecryptionapp

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import android.util.Base64

class MainActivity : AppCompatActivity() {

    private lateinit var secretKey: SecretKey
    private var encryptedMessage: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val etMessage: EditText = findViewById(R.id.etMessage)
        val btnEncrypt: Button = findViewById(R.id.btnEncrypt)
        val btnDecrypt: Button = findViewById(R.id.btnDecrypt)
        val tvResult: TextView = findViewById(R.id.tvResult)

        // Generate AES key when app starts
        secretKey = generateAESKey()

        btnEncrypt.setOnClickListener {
            val message = etMessage.text.toString()
            if (message.isNotEmpty()) {
                encryptedMessage = encryptMessage(message, secretKey)
                tvResult.text = "Encrypted Message: $encryptedMessage"
            } else {
                tvResult.text = "Please enter a message to encrypt."
            }
        }

        btnDecrypt.setOnClickListener {
            if (encryptedMessage != null) {
                val decryptedMessage = decryptMessage(encryptedMessage!!, secretKey)
                tvResult.text = "Decrypted Message: $decryptedMessage"
            } else {
                tvResult.text = "No encrypted message to decrypt."
            }
        }
    }

    // AES Encryption Helper Functions
    private fun generateAESKey(): SecretKey {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, SecureRandom()) // 256-bit AES key
        return keyGen.generateKey()
    }

    private fun encryptMessage(message: String, secretKey: SecretKey): String {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val iv = ByteArray(16)
        SecureRandom().nextBytes(iv)
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec)

        val encrypted = cipher.doFinal(message.toByteArray(Charsets.UTF_8))
        val encryptedMessage = Base64.encodeToString(encrypted, Base64.DEFAULT)
        val encodedIV = Base64.encodeToString(iv, Base64.DEFAULT)

        return "$encodedIV:$encryptedMessage"
    }

    private fun decryptMessage(encryptedMessage: String, secretKey: SecretKey): String {
        val parts = encryptedMessage.split(":")
        val iv = Base64.decode(parts[0], Base64.DEFAULT)
        val encryptedBytes = Base64.decode(parts[1], Base64.DEFAULT)

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        val ivSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec)

        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes, Charsets.UTF_8)
    }
}
