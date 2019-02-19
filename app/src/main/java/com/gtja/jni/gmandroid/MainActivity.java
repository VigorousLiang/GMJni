package com.gtja.jni.gmandroid;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import com.gtja.common.jni.IJniInterface;
import com.gtja.util.HexUtil;
import com.guotai.dazhihui.R;

public class MainActivity extends AppCompatActivity implements View.OnClickListener {

    private EditText et;
    private TextView tvResult;
    private Button btnSm3;
    private Button btnSm2Sign;
    private Button btnSm2Verify;
    private Button btnSm2Encrypt;
    private Button btnSm2Decrypt;
    private Button btnSm4Encrypt;
    private Button btnSm4Decrypt;
    String signedHexStr;
    String sm2EncryptedHexStr;
    String sm4EncryptedHexStr;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        IJniInterface.initJNIEnv(getApplicationContext());
        IJniInterface.genAesId("111","2018");
        // Example of a call to a native method
        et = (EditText) findViewById(R.id.et_input);
        tvResult = (TextView) findViewById(R.id.tv_result);
        btnSm3 = (Button) findViewById(R.id.btn_sm3);
        btnSm3.setOnClickListener(this);
        btnSm2Sign = (Button) findViewById(R.id.btn_sm2sign);
        btnSm2Sign.setOnClickListener(this);
        btnSm2Verify = (Button) findViewById(R.id.btn_sm2verify);
        btnSm2Verify.setOnClickListener(this);
        btnSm2Encrypt = (Button) findViewById(R.id.btn_sm2encrypt);
        btnSm2Encrypt.setOnClickListener(this);
        btnSm2Decrypt = (Button) findViewById(R.id.btn_sm2decrypt);
        btnSm2Decrypt.setOnClickListener(this);
        btnSm4Encrypt = (Button) findViewById(R.id.btn_sm4encrypt);
        btnSm4Encrypt.setOnClickListener(this);
        btnSm4Decrypt = (Button) findViewById(R.id.btn_sm4decrypt);
        btnSm4Decrypt.setOnClickListener(this);
    }

    @Override
    public void onClick(View v) {
        String text = et.getText().toString().trim();
        int id = v.getId();
        switch (id) {
            case R.id.btn_sm3:
                tvResult.setText(IJniInterface.digestSM3(text.getBytes()));
                break;
            case R.id.btn_sm2sign:
                signedHexStr = IJniInterface.signSM2WithPrivateKey(text.getBytes(), IJniInterface.sm2PrivateKey);
                if (!TextUtils.isEmpty(signedHexStr)) {
                    tvResult.setText(signedHexStr);
                }
                break;
            case R.id.btn_sm2verify:
                if (!TextUtils.isEmpty(signedHexStr)) {
                    Log.e("verify", "" + IJniInterface.verifySM2WithPublicKey(HexUtil.decode(signedHexStr), text.getBytes(), IJniInterface.sm2PublicKey));
                }
                break;
            case R.id.btn_sm2encrypt:
                sm2EncryptedHexStr = IJniInterface.encryptSM2WithPublicKey(text.getBytes(), IJniInterface.sm2PublicKey);
                if (!TextUtils.isEmpty(sm2EncryptedHexStr)) {
                    tvResult.setText(sm2EncryptedHexStr);
                }
                break;
            case R.id.btn_sm2decrypt:
                if (!TextUtils.isEmpty(sm2EncryptedHexStr)) {
                    tvResult.setText(IJniInterface.decryptSM2WithPrivateKey(HexUtil.decode(sm2EncryptedHexStr), IJniInterface.sm2PrivateKey));
                }
                break;
            case R.id.btn_sm4encrypt:
                sm4EncryptedHexStr = IJniInterface.encryptWithSM4(text.getBytes(), IJniInterface.key, IJniInterface.iv);
                if (!TextUtils.isEmpty(sm4EncryptedHexStr)) {
                    tvResult.setText(sm4EncryptedHexStr);
                }
                break;
            case R.id.btn_sm4decrypt:
                if (!TextUtils.isEmpty(sm4EncryptedHexStr)) {
                    tvResult.setText(IJniInterface.decryptWithSM4(HexUtil.decode(sm4EncryptedHexStr), IJniInterface.key, IJniInterface.iv));
                }
                break;
        }
    }
}
