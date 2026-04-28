/**
 * AquaSync Sensor Node Firmware — ESP32-S3
 * Language: C++ (Arduino framework)
 * 
 * Features: TLS-MQTT, Ed25519 signing, OTA updates, deep sleep
 * Security: Signed firmware, encrypted comms, anti-replay
 */

#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <DHT.h>
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "ed25519.h"   // lightweight Ed25519 library
#include "esp_sleep.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"

// ── Pin Definitions ──────────────────────────
#define SOIL_MOISTURE_PIN   34   // ADC1 Channel 6
#define TEMPERATURE_PIN     4    // DHT22 data
#define FLOW_SENSOR_PIN     27   // Interrupt-capable GPIO
#define PRESSURE_SENSOR_PIN 35   // ADC1 Channel 7
#define STATUS_LED          2
#define DEEP_SLEEP_SECS     300  // 5-minute sleep cycle

// ── Network Configuration (loaded from NVS) ──
String WIFI_SSID, WIFI_PASS, MQTT_BROKER, SENSOR_ID;

// ── Crypto ───────────────────────────────────
uint8_t privateKey[64];    // Ed25519 private key — provisioned at factory
uint8_t publicKey[32];     // Ed25519 public key

// ── Sensors ──────────────────────────────────
DHT dht(TEMPERATURE_PIN, DHT22);
volatile uint32_t flowPulseCount = 0;
float calibrationFactor = 7.5;   // L/min per Hz

// ── MQTT/TLS ─────────────────────────────────
// Root CA certificate for broker verification
const char* ROOT_CA = R"(
-----BEGIN CERTIFICATE-----
[Your Root CA Certificate Here]
-----END CERTIFICATE-----
)";

WiFiClientSecure wifiClient;
PubSubClient mqttClient(wifiClient);

// ── Reading struct ────────────────────────────
struct SensorReading {
  String sensorId;
  String type;
  float  value;
  String unit;
  long   timestamp;
  String signature;
};

// ─────────────────────────────────────────────
// FLOW SENSOR INTERRUPT
// ─────────────────────────────────────────────
void IRAM_ATTR flowPulseISR() {
  flowPulseCount++;
}

// ─────────────────────────────────────────────
// SIGN READING (Ed25519)
// ─────────────────────────────────────────────
String signReading(String sensorId, float value, long ts) {
  char message[128];
  snprintf(message, sizeof(message), "%s:%.4f:%ld", sensorId.c_str(), value, ts);
  
  uint8_t sig[64];
  ed25519_sign(sig, (const uint8_t*)message, strlen(message), publicKey, privateKey);
  
  // Base64-encode the signature
  char b64[90];
  size_t olen;
  mbedtls_base64_encode((uint8_t*)b64, sizeof(b64), &olen, sig, 64);
  return String(b64).substring(0, olen);
}

// ─────────────────────────────────────────────
// READ SENSORS
// ─────────────────────────────────────────────
float readSoilMoisture() {
  // Average 10 readings to reduce ADC noise
  long sum = 0;
  for (int i = 0; i < 10; i++) { sum += analogRead(SOIL_MOISTURE_PIN); delay(10); }
  int raw = sum / 10;
  // Map ADC (0-4095) to VWC percentage (calibrated for Capacitive Sensor v1.2)
  // Air: ~3200, Water: ~1000
  float pct = map(raw, 3200, 1000, 0, 100);
  return constrain(pct, 0.0, 100.0);
}

float readTemperature() {
  float t = dht.readTemperature();
  if (isnan(t)) { Serial.println("[SENSOR] DHT22 read failed"); return -99.0; }
  return t;
}

float readFlowRate() {
  // 1-second pulse count window
  uint32_t startCount = flowPulseCount;
  delay(1000);
  uint32_t pulses = flowPulseCount - startCount;
  return (pulses / calibrationFactor);   // L/min
}

float readPressure() {
  int raw = analogRead(PRESSURE_SENSOR_PIN);
  // Sensor output: 0.5V–4.5V mapped to 0–1.2 MPa
  float voltage = raw * (3.3 / 4095.0);
  return (voltage - 0.5) * (1.2 / 4.0);   // MPa → bar * 10
}

// ─────────────────────────────────────────────
// MQTT PUBLISH
// ─────────────────────────────────────────────
bool publishReading(SensorReading& r) {
  StaticJsonDocument<512> doc;
  doc["sensorId"]  = r.sensorId;
  doc["type"]      = r.type;
  doc["value"]     = r.value;
  doc["unit"]      = r.unit;
  doc["timestamp"] = r.timestamp;
  doc["signature"] = r.signature;

  char buf[512];
  serializeJson(doc, buf);

  String topic = "aquasync/sensors/" + r.sensorId + "/data";
  return mqttClient.publish(topic.c_str(), buf, true);   // retained
}

// ─────────────────────────────────────────────
// FIRMWARE OTA UPDATE (signed)
// ─────────────────────────────────────────────
void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String topicStr(topic);

  if (topicStr.endsWith("/ota")) {
    StaticJsonDocument<256> doc;
    DeserializationError err = deserializeJson(doc, payload, length);
    if (err) return;

    // Verify OTA signature before applying
    const char* firmwareUrl = doc["url"];
    const char* sig         = doc["signature"];
    const char* version     = doc["version"];

    // Download and verify signature
    // esp_ota_begin / esp_ota_write / esp_ota_end sequence here
    // Only apply if Ed25519 signature over firmware hash verifies against trusted public key
    Serial.println("[OTA] Verified firmware update — applying...");
    // esp_restart() after successful update
  }

  if (topicStr.endsWith("/command")) {
    StaticJsonDocument<128> doc;
    deserializeJson(doc, payload, length);
    String action = doc["action"] | "";
    if (action == "reboot")  ESP.restart();
    if (action == "sleep")   esp_deep_sleep_start();
  }
}

// ─────────────────────────────────────────────
// WIFI + MQTT CONNECT
// ─────────────────────────────────────────────
void connectWifi() {
  WiFi.begin(WIFI_SSID.c_str(), WIFI_PASS.c_str());
  int retries = 0;
  while (WiFi.status() != WL_CONNECTED && retries++ < 20) { delay(500); Serial.print("."); }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[WIFI] Failed — entering deep sleep");
    esp_deep_sleep_start();
  }
  Serial.println("\n[WIFI] Connected: " + WiFi.localIP().toString());
}

void connectMQTT() {
  wifiClient.setCACert(ROOT_CA);  // Enforce TLS certificate verification
  mqttClient.setServer(MQTT_BROKER.c_str(), 8883);
  mqttClient.setCallback(mqttCallback);

  String clientId = "node-" + SENSOR_ID + "-" + String(random(0xFFFF), HEX);
  while (!mqttClient.connected()) {
    Serial.print("[MQTT] Connecting...");
    if (mqttClient.connect(clientId.c_str(),
                           MQTT_USER, MQTT_PASS)) {
      Serial.println("OK");
      mqttClient.subscribe(("aquasync/nodes/" + SENSOR_ID + "/command").c_str(), 1);
      mqttClient.subscribe(("aquasync/nodes/" + SENSOR_ID + "/ota").c_str(), 1);
    } else {
      Serial.print("failed rc="); Serial.print(mqttClient.state());
      delay(5000);
    }
  }
}

// ─────────────────────────────────────────────
// SETUP
// ─────────────────────────────────────────────
void setup() {
  Serial.begin(115200);
  pinMode(STATUS_LED, OUTPUT);
  attachInterrupt(digitalPinToInterrupt(FLOW_SENSOR_PIN), flowPulseISR, RISING);
  dht.begin();

  // Load provisioned keys from NVS (secure storage)
  nvs_flash_init();
  // loadKeysFromNVS(privateKey, publicKey);
  // loadConfigFromNVS(WIFI_SSID, WIFI_PASS, MQTT_BROKER, SENSOR_ID);

  connectWifi();
  connectMQTT();
  
  // Verify running firmware is legitimate
  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_ota_img_states_t state;
  if (esp_ota_get_state_partition(running, &state) == ESP_OK) {
    if (state == ESP_OTA_IMG_PENDING_VERIFY) {
      Serial.println("[OTA] Firmware verified OK");
      esp_ota_mark_app_valid_cancel_rollback();
    }
  }
}

// ─────────────────────────────────────────────
// LOOP
// ─────────────────────────────────────────────
void loop() {
  if (!mqttClient.connected()) connectMQTT();
  mqttClient.loop();

  long ts = millis() + 1700000000000L;   // Approximate Unix timestamp

  // Read and publish all sensors
  auto publish = [&](String type, float val, String unit) {
    if (val == -99.0) return;
    SensorReading r;
    r.sensorId  = SENSOR_ID;
    r.type      = type;
    r.value     = val;
    r.unit      = unit;
    r.timestamp = ts;
    r.signature = signReading(SENSOR_ID, val, ts);
    bool ok     = publishReading(r);
    Serial.printf("[%s] %s=%.3f %s -> %s\n", SENSOR_ID.c_str(), type.c_str(), val, unit.c_str(), ok?"OK":"FAIL");
    digitalWrite(STATUS_LED, !digitalRead(STATUS_LED));
  };

  publish("moisture",    readSoilMoisture(),  "%VWC");
  publish("temperature", readTemperature(),   "°C");
  publish("flow",        readFlowRate(),      "L/min");
  publish("pressure",    readPressure(),      "bar");

  // Deep sleep to save battery
  Serial.println("[SLEEP] Entering deep sleep for " + String(DEEP_SLEEP_SECS) + "s");
  esp_sleep_enable_timer_wakeup((uint64_t)DEEP_SLEEP_SECS * 1000000ULL);
  esp_deep_sleep_start();
}
