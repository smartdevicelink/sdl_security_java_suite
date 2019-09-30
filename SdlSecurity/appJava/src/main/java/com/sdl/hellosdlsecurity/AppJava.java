package com.sdl.hellosdlsecurity;

import com.smartdevicelink.sdlsecurity.SdlSecurity;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class AppJava {
    private static final int BUFFER_SIZE = 4096;

    public static void main(String[] args) {
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {

                try {
                    ServerSocket listener = new ServerSocket(1111);
                    System.out.println("Server is running...");
                    while (true) {
                        Socket clientSocket = listener.accept();
                        System.out.println("Client connected");

                        // Receive & send unencrypted message
                        DataInputStream dIn = new DataInputStream(clientSocket.getInputStream());
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytes = dIn.read(buffer);
                        System.out.println("From client: " + new String(buffer, StandardCharsets.UTF_8).substring(0, bytes));

                        DataOutputStream dOut = new DataOutputStream(clientSocket.getOutputStream());
                        String msg = "I hear you!";
                        System.out.println("To client: " + msg);
                        dOut.write(msg.getBytes());

                        // Init TLS engine
                        SdlSecurity sdlSecurity = new SdlSecurity();
                        sdlSecurity.initialize();
                        System.out.println("Waiting for SdlSecurity to initialize");
                        Thread.sleep(2000);

                        // Do handshake w/ client
                        System.out.println("Handshake step 1: receiving ClientHello");
                        byte[] bufferOutput = new byte[BUFFER_SIZE];
                        dIn.read(buffer);
                        System.out.println("Handshake step 2: sending ServerHello");
                        sdlSecurity.runHandshake(buffer, bufferOutput);
                        dOut.write(bufferOutput);
                        System.out.println("Handshake step 3: receiving change cipher spec");
                        dIn.read(buffer);
                        sdlSecurity.runHandshake(buffer, bufferOutput);
                        System.out.println("Handshake step 4: finished");
                        dOut.write(bufferOutput);
                        // end handshake

                        // receive an encrypted message
                        dIn.read(buffer);
                        bytes = sdlSecurity.decryptData(buffer, bufferOutput);
                        System.out.println("From client: " + new String(bufferOutput, StandardCharsets.UTF_8).substring(0, bytes));
                        msg = "I hear you! (encrypted)";
                        System.out.println("To client: " + msg);
                        sdlSecurity.encryptData(msg.getBytes(), bufferOutput);
                        dOut.write(bufferOutput);

                        // shutdown
                        System.out.println("shutdown");
                        sdlSecurity.shutDown();

                    }
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }
            }
        });

        t.start();
    }
}