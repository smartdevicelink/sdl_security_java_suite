package com.smartdevicelink.security;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {

    private final String TAG = "SdlSecurity_Main";
    private final int BUFFER_SIZE = 4096;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    ServerSocket listener = new ServerSocket(1111);
                    Log.i(TAG, "Server is running...");
                    while (true) {
                        Socket clientSocket = listener.accept();
                        Log.i(TAG, "Client connected");

                        // Receive & send unencrypted message
                        DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytes = dIn.read(buffer);
                        Log.i(TAG, "From client: " + new String(buffer, StandardCharsets.UTF_8).substring(0, bytes));

                        DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
                        String msg = "I hear you!";
                        Log.i(TAG, "To client: " + msg);
                        dOut.write(msg.getBytes());

                        // Init TLS engine
                        SdlSecurity sdlSecurity = new SdlSecurity();
                        sdlSecurity.initialize();
                        Log.i(TAG, "Waiting for SdlSecurity to initialize");
                        Thread.sleep(2000);

                        // Do handshake w/ client
                        Log.i(TAG, "Handshake step 1: receiving ClientHello");
                        byte[] bufferOutput = new byte[BUFFER_SIZE];
                        dIn.read(buffer);
                        Log.i(TAG, "Handshake step 2: sending ServerHello");
                        sdlSecurity.runHandshake(buffer, bufferOutput);
                        dOut.write(bufferOutput);
                        Log.i(TAG, "Handshake step 3: receiving change cipher spec");
                        dIn.read(buffer);
                        sdlSecurity.runHandshake(buffer, bufferOutput);
                        Log.i(TAG, "Handshake step 4: finished");
                        dOut.write(bufferOutput);
                        // end handshake

                        // receive an encrypted message
                        dIn.read(buffer);
                        bytes = sdlSecurity.decryptData(buffer, bufferOutput);
                        Log.i(TAG, "From client: " + new String(bufferOutput, StandardCharsets.UTF_8).substring(0, bytes));
                        msg = "I hear you! (encrypted)";
                        Log.i(TAG, "To client: " + msg);
                        sdlSecurity.encryptData(msg.getBytes(), bufferOutput);
                        dOut.write(bufferOutput);

                        // shutdown
                        Log.i(TAG, "shutdown");
                        sdlSecurity.shutDown();

                    }
                } catch (Exception e) {
                    Log.e(TAG, e.getMessage());
                }
            }
        });

        t.start();

    }
}
