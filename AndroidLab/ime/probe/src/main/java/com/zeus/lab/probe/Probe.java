package com.zeus.lab.probe;
import android.app.Activity;
import android.os.Bundle;
import android.widget.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

/** Controlled CI app only; never bundled in the production worker image. */
public final class Probe extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout column=new LinearLayout(this);column.setOrientation(LinearLayout.VERTICAL);column.setPadding(32,64,32,32);
        EditText input=new EditText(this);input.setHint("ZEUS probe message");input.setContentDescription("probeInput");column.addView(input);
        Button send=new Button(this);send.setText("Send probe");send.setContentDescription("probeSend");column.addView(send);
        TextView result=new TextView(this);result.setContentDescription("probeResult");column.addView(result);
        send.setOnClickListener(v->{String text=input.getText().toString();new Thread(()->{
            try {
                HttpURLConnection connection=(HttpURLConnection)new URL("https://zeus-probe.invalid:8091/probe").openConnection();
                connection.setRequestMethod("POST");connection.setDoOutput(true);connection.setConnectTimeout(10000);connection.setReadTimeout(30000);
                connection.setRequestProperty("Content-Type","text/plain; charset=utf-8");connection.getOutputStream().write(text.getBytes(StandardCharsets.UTF_8));
                int code=connection.getResponseCode();connection.disconnect();runOnUiThread(()->result.setText("HTTP "+code));
            }catch(Exception e){runOnUiThread(()->result.setText(e.getClass().getSimpleName()));}
        }).start();});
        setContentView(column);
    }
}
