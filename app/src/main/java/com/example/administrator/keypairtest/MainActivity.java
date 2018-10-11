package com.example.administrator.keypairtest;

import android.os.Build;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity implements View.OnClickListener{
    private String pubKeyStr;
    private String priKeyStr;
    private Cipher cipher;
    private TextView textView;
    private EditText editText;
    private Button encode;
    private Button decode;

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState){
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        textView=(TextView)findViewById(R.id.textView);
        editText=(EditText)findViewById(R.id.et);
        encode=(Button)findViewById(R.id.btn_encode);
        decode=(Button)findViewById(R.id.btn_decode);
        encode.setOnClickListener(this);
        decode.setOnClickListener(this);
        try {
            //1，获取cipher 对象
            cipher = Cipher.getInstance("RSA");
           /* KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec
                     .Builder(KEYSTORE_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                     .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                     .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                     .setKeySize(4096)
                     .build();*/
            //2，通过秘钥对生成器KeyPairGenerator 生成公钥和私钥
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
//使用公钥进行加密，私钥进行解密（也可以反过来使用）
            PublicKey publicKey = keyPair.getPublic();
            pubKeyStr= Base64.getEncoder().encodeToString(publicKey.getEncoded());
            Log.i("tag","init_publicKey="+pubKeyStr);
            PrivateKey privateKey = keyPair.getPrivate();
            priKeyStr=Base64.getEncoder().encodeToString(privateKey.getEncoded());
            Log.i("tag","init_privatekey="+priKeyStr);
//3,使用公钥初始化密码器
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
//4，执行加密操作
            byte[] result = cipher.doFinal("123456".getBytes());
            Base64.Encoder encoder = Base64.getEncoder();
            String encode = encoder.encodeToString(result);
            Log.i("tag",encode);
//使用私钥初始化密码器
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
//执行解密操作
            byte[] deResult = cipher.doFinal(result);
            Log.i("tag",new String(deResult));
            textView.setText(new String(deResult));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static PublicKey getPublicKey(String key) throws Exception {
        byte[] keyBytes;
        keyBytes = decryptBASE64(key);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static PrivateKey getPrivateKey(String key) throws Exception {
        byte[] keyBytes;
        Log.i("tag","私密:=="+key);
        keyBytes = decryptBASE64(key);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA","BC");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    public void onClick(View v) {
        byte[] result=new byte[1024];
        switch (v.getId()){
            case R.id.btn_encode:
                try {
                    //3,使用公钥初始化密码器
                    cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(pubKeyStr));
//4，执行加密操作
                    String str = editText.getText().toString().trim();
                    Log.i("tag","str="+str);
                    result = cipher.doFinal(str.getBytes());
                    String encodeStr=encryptBASE64(result);
                    textView.setText(encodeStr);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                break;
            case R.id.btn_decode:
                //使用私钥初始化密码器
                try {
                    Log.i("tag",textView.getText().toString());
                    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
                    PrivateKey privatekey = keyPair.getPrivate();
                    //cipher.init(Cipher.DECRYPT_MODE, privatekey);
                    cipher.init(Cipher.DECRYPT_MODE, getPrivateKey(priKeyStr));
                    //执行解密操作
                    byte[] deResult = cipher.doFinal(decryptBASE64(textView.getText().toString()));
                   // byte[] deResult = cipher.doFinal(result);
                    Log.i("tag",new String(deResult));
                    textView.setText(new String(deResult));
                } catch (Exception e) {
                    e.printStackTrace();
                }

                break;
        }
    }

    /**
     * BASE64Encoder 加密
     *
     * @param data
     *            要加密的数据
     * @return 加密后的字符串
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static String encryptBASE64(byte[] data) {
        // BASE64Encoder encoder = new BASE64Encoder();
        // String encode = encoder.encode(data);
        // 从JKD 9开始rt.jar包已废除，从JDK 1.8开始使用java.util.Base64.Encoder
        Base64.Encoder encoder = Base64.getEncoder();
        String encode = encoder.encodeToString(data);
        return encode;
    }
    /**
     * BASE64Decoder 解密
     *
     * @param data
     *            要解密的字符串
     * @return 解密后的byte[]
     * @throws Exception
     */
    @RequiresApi(api = Build.VERSION_CODES.O)
    public static byte[] decryptBASE64(String data) throws Exception {
        // BASE64Decoder decoder = new BASE64Decoder();
        // byte[] buffer = decoder.decodeBuffer(data);
        // 从JKD 9开始rt.jar包已废除，从JDK 1.8开始使用java.util.Base64.Decoder
        Base64.Decoder decoder = Base64.getDecoder();
        byte[] buffer = decoder.decode(data);
        return buffer;
    }
}
