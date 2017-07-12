/*
 *  This sketch demonstrates how to scan WiFi networks.
 *  The API is almost the same as with the WiFi Shield library,
 *  the most obvious difference being the different file you need to include:
 */
#include "WiFi.h"
#include "Arduino.h"
#include <uECC.h>
#include "hwcrypto/sha.h"

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define SHA256_SIZE 32

static int RNG(uint8_t *dest, unsigned size) {
        // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of
        // random noise). This can take a long time to generate random data if the result of analogRead(0)
        // doesn't change very frequently.
        while (size) {
                uint8_t val = 0;
                for (unsigned i = 0; i < 8; ++i) {
                        int count = random(1,10);
                        val = (val << 1) | (count & 0x01);
                }
                *dest = val;
                ++dest;
                --size;
        }
        // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
        return 1;
}



void setup()
{
    Serial.begin(115200);

    // Set WiFi to station mode and disconnect from an AP if it was previously connected
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    Serial.println("Setup done");
    uECC_set_rng(&RNG);

}

void gen_random(char *s, const int len) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
}


void ECC_test(){
  const struct uECC_Curve_t * curve = uECC_secp160r1();
  uint8_t private1[21];
  uint8_t private2[21];

  uint8_t public1[40];
  uint8_t public2[40];

  uint8_t secret1[20];
  uint8_t secret2[20];


  unsigned long a = millis();
  uECC_make_key(public1, private1, curve);
  unsigned long b = millis();

  Serial.print("Made key 1 in "); Serial.println(b-a);
  a = millis();
  uECC_make_key(public2, private2, curve);
  b = millis();
  Serial.print("Made key 2 in "); Serial.println(b-a);


  a = millis();
  int r = uECC_shared_secret(public2, private1, secret1, curve);
  b = millis();
  Serial.print("Shared secret 1 in "); Serial.println(b-a);
  if (!r) {
          Serial.print("shared_secret() failed (1)\n");
          return;
  }

  a = millis();
  r = uECC_shared_secret(public1, private2, secret2, curve);
  b = millis();
  Serial.print("Shared secret 2 in "); Serial.println(b-a);
  if (!r) {
          Serial.print("shared_secret() failed (2)\n");
          return;
  }

  if (memcmp(secret1, secret2, 20) != 0) {
          Serial.print("Shared secrets are not identical!\n");
  } else {
          Serial.print("Shared secrets are identical\n");
  }





  char hello[2048];

  gen_random(hello,2048);
  byte hash[32];
  Serial.print("Message :");Serial.println(hello);


  esp_sha(SHA2_256,reinterpret_cast<const unsigned char *> (hello),2048,hash);
  Serial.print("Hash :");
  /* hash now contains our 32 byte hash */
  for (byte i=0; i < NELEMS(hash); i++){
          if (hash[i]<0x10) { Serial.print('0'); }
          Serial.print(hash[i], HEX);
  }

  Serial.println("---");
  Serial.print("Signature (private 1)):");

  uint8_t signature[40];
  uECC_sign(private1, hash, SHA256_SIZE,signature, curve);

  for (byte i=0; i < NELEMS(signature); i++)
  {
          if (signature[i]<0x10) { Serial.print('0'); }
          Serial.print(signature[i], HEX);
  }

  Serial.println("---");
  Serial.printf("Check against public1 = %d\n", uECC_verify(public1, hash, SHA256_SIZE,signature, curve));
  Serial.printf("Check against public2 = %d\n", uECC_verify(public2, hash, SHA256_SIZE,signature, curve));
  Serial.print("Signature (private 2)):");

  uint8_t signature2[40];
  uECC_sign(private2, hash, SHA256_SIZE,signature2, curve);

  for (byte i=0; i < NELEMS(signature2); i++)
  {
          if (signature[i]<0x10) { Serial.print('0'); }
          Serial.print(signature2[i], HEX);
  }

  Serial.println("---");
  Serial.printf("Check against public1 = %d\n", uECC_verify(public1, hash, SHA256_SIZE,signature2, curve));
  Serial.printf("Check against public2 = %d\n", uECC_verify(public2, hash, SHA256_SIZE,signature2, curve));

}

void loop()
{
    Serial.println("test start");
    ECC_test();
    // Wait a bit before scanning again
    delay(5000);
}
