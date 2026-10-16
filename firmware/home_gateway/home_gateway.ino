// Home MCP Guardian: home gateway on an ESP32-C3, connected to the Mac hub over USB (no Wi-Fi, no credentials).
// It is the real "home gateway" the guardian watches: one heartbeat line every 60 s, so unplugging it (or a crash) is
// detected as late after 3 min and offline after 5 min, exactly like the simulated gateway. The BOOT button (GPIO9 on
// ESP32-C3 boards, including Seeed XIAO ESP32C3 and C3 SuperMini) is the parent's button: a short press says "I'm OK",
// a long press (1.5 s) asks the family for help. The hub accepts these lines only after the hello line with this id.
//
// Protocol (one JSON object per line, 115200 baud, USB CDC):
//   {"t":"hello","id":"hmg-home-gateway","fw":"hmg-gw-1","chip":"esp32c3","beatMs":60000}
//   {"t":"beat","n":<count>,"upMs":<uptime>}
//   {"t":"button","press":"short"|"long","n":<count>}
// Commands from the hub (single characters): '?' -> hello, 'h' -> one beat now.
//
// Build: arduino-cli compile --fqbn esp32:esp32:esp32c3:CDCOnBoot=cdc firmware/home_gateway
//        (Seeed XIAO ESP32C3: --fqbn esp32:esp32:XIAO_ESP32C3)

static const char* GATEWAY_ID = "hmg-home-gateway";
static const char* FIRMWARE_ID = "hmg-gw-1";
static const int BUTTON_PIN = 9;                       // BOOT button, active low
static const unsigned long BEAT_MS = 60000;
static const unsigned long LONG_PRESS_MS = 1500;
static const unsigned long DEBOUNCE_MS = 30;

unsigned long beatCount = 0;
unsigned long pressCount = 0;
unsigned long lastBeatAt = 0;
int stableState = HIGH;
int lastReading = HIGH;
unsigned long lastChangeAt = 0;
unsigned long pressedAt = 0;

void hello() {
  Serial.print("{\"t\":\"hello\",\"id\":\"");
  Serial.print(GATEWAY_ID);
  Serial.print("\",\"fw\":\"");
  Serial.print(FIRMWARE_ID);
  Serial.print("\",\"chip\":\"esp32c3\",\"beatMs\":");
  Serial.print(BEAT_MS);
  Serial.println("}");
}

void beat() {
  beatCount++;
  lastBeatAt = millis();
  Serial.print("{\"t\":\"beat\",\"n\":");
  Serial.print(beatCount);
  Serial.print(",\"upMs\":");
  Serial.print(millis());
  Serial.println("}");
}

void button(const char* press) {
  pressCount++;
  Serial.print("{\"t\":\"button\",\"press\":\"");
  Serial.print(press);
  Serial.print("\",\"n\":");
  Serial.print(pressCount);
  Serial.println("}");
}

void setup() {
  Serial.begin(115200);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  delay(1500);                                         // let USB CDC enumerate on the Mac
  hello();
  beat();                                              // a gateway reports right away when it comes up
}

void loop() {
  while (Serial.available() > 0) {
    char c = static_cast<char>(Serial.read());
    if (c == '?') hello();
    else if (c == 'h') beat();
  }

  unsigned long now = millis();
  if (now - lastBeatAt >= BEAT_MS) beat();

  int reading = digitalRead(BUTTON_PIN);
  if (reading != lastReading) { lastChangeAt = now; lastReading = reading; }
  if (now - lastChangeAt > DEBOUNCE_MS && reading != stableState) {
    stableState = reading;
    if (stableState == LOW) pressedAt = now;
    else button(now - pressedAt >= LONG_PRESS_MS ? "long" : "short");
  }
  delay(5);
}
