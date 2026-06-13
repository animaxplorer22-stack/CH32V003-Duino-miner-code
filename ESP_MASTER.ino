/*
  ESP32/ESP8266 DUCO Master - Controls CH32V003 slaves via I2C
  Wire connections:
  ESP32: SDA=21, SCL=22
  ESP8266: SDA=4, SCL=5
*/

#include <WiFi.h>
#include <Wire.h>

// ========== CHANGE THESE ==========
const char* ssid = "YOUR_WIFI";
const char* password = "YOUR_PASS";
const char* duco_user = "YOUR_USERNAME";
const char* rig_name = "CH32V003_Slave";
// ===================================

const char* server = "server.duinocoin.com";
const int port = 2811;

WiFiClient client;

// I2C settings
#define I2C_SDA 21  // ESP32: 21, ESP8266: 4
#define I2C_SCL 22  // ESP32: 22, ESP8266: 5
#define SLAVE_ADDR 0x08

uint32_t slave_nonce = 0;
bool has_job = false;
String last_hash = "";
String target_hash = "";
int difficulty = 10;
unsigned long accepted = 0;
unsigned long rejected = 0;

void connectWiFi() {
  Serial.print("Connecting to WiFi");
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected!");
}

bool getJob() {
  if (!client.connect(server, port)) return false;
  
  client.print("JOB," + String(duco_user) + "\n");
  
  unsigned long start = millis();
  while (!client.available() && millis() - start < 8000) delay(10);
  
  if (client.available()) {
    String resp = client.readStringUntil('\n');
    resp.trim();
    
    int first = resp.indexOf(',');
    int second = resp.indexOf(',', first + 1);
    
    if (first > 0 && second > 0) {
      last_hash = resp.substring(0, first);
      target_hash = resp.substring(first + 1, second);
      difficulty = resp.substring(second + 1).toInt();
      if (difficulty < 1) difficulty = 10;
      return true;
    }
  }
  client.stop();
  return false;
}

bool submitShare(uint32_t nonce) {
  if (!client.connect(server, port)) return false;
  
  client.print(String(nonce) + ",0,ESP_Master," + String(rig_name) + "\n");
  
  unsigned long start = millis();
  while (!client.available() && millis() - start < 10000) delay(10);
  
  if (client.available()) {
    String resp = client.readStringUntil('\n');
    resp.trim();
    client.stop();
    return resp.startsWith("GOOD");
  }
  
  client.stop();
  return false;
}

void sendJobToSlave() {
  Wire.beginTransmission(SLAVE_ADDR);
  Wire.write('J');
  for (int i = 0; i < last_hash.length(); i++) Wire.write(last_hash[i]);
  for (int i = 0; i < target_hash.length(); i++) Wire.write(target_hash[i]);
  Wire.endTransmission();
  has_job = true;
}

uint32_t readNonceFromSlave() {
  Wire.requestFrom(SLAVE_ADDR, 4);
  if (Wire.available() >= 4) {
    uint32_t nonce = 0;
    nonce |= (uint32_t)Wire.read() << 24;
    nonce |= (uint32_t)Wire.read() << 16;
    nonce |= (uint32_t)Wire.read() << 8;
    nonce |= Wire.read();
    return nonce;
  }
  return 0;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  
  Serial.println("\nESP DUCO Master for CH32V003 Starting...");
  
  Wire.begin(I2C_SDA, I2C_SCL);
  Wire.setClock(100000);
  
  connectWiFi();
  
  Serial.println("Master ready. Sending first job...");
}

void loop() {
  static unsigned long lastJob = 0;
  
  if (!has_job) {
    if (getJob()) {
      sendJobToSlave();
      lastJob = millis();
      Serial.print("Job sent. Diff: ");
      Serial.println(difficulty);
    }
    delay(100);
  } else {
    uint32_t nonce = readNonceFromSlave();
    if (nonce != 0) {
      Serial.print("Slave found nonce: ");
      Serial.println(nonce);
      
      if (submitShare(nonce)) {
        accepted++;
        Serial.println("Share ACCEPTED!");
      } else {
        rejected++;
        Serial.println("Share REJECTED!");
      }
      has_job = false;
    }
    
    // Timeout after 60 seconds
    if (millis() - lastJob > 60000) {
      Serial.println("Job timeout, getting new job");
      has_job = false;
    }
  }
  
  // Keep WiFi alive
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }
  
  delay(10);
}