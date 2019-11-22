#include <cryptoauth.h>

// Change to AtSha204() to use the 204
AtSha204 sha = AtSha204();

void setup() {
    Serial.begin(9600);
    sha.enableDebug(&Serial);
}

void loop() {
    /* If you haven't personalized your device yet, you will recieve
     * this on your serial terminal:
       ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000
       Success

       Otherwise, you'll get actual random bytes.
    */
    if (0 == sha.getRandom()){
        Serial.println("Success");
        sha.rsp.dumpHex(&Serial);
    }
    else{
        Serial.println("Failure");
    }

    delay(1000);


}
