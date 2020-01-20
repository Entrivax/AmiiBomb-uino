#include <SPI.h>
#include "MFRC522.h"
#include "SerialCommand.h"

#define RST_PIN         9
#define SS_PIN          10
#define Begin_of_Message "\x02"
#define End_of_Message "\x03"

MFRC522 mfrc522(SS_PIN, RST_PIN);
SerialCommand SCmd; 

void setup()
{
  Serial.begin(115200);
  SPI.begin();
  mfrc522.PCD_Init();
  SCmd.addCommand("/AMII", PingPong);
  SCmd.addCommand("/NTAG_HERE", NTAG_Here);
  SCmd.addCommand("/GET_NTAG_UID", NTAG_UID);
  SCmd.addCommand("/NTAG_HALT", NTAG_Halt);
  SCmd.addCommand("/READ_AMIIBO", Read_Amiibo);
  SCmd.addCommand("/WRITE_AMIIBO", Write_Amiibo);
  SCmd.addCommand("/RESTORE_AMIIBO", Restore_Amiibo);
}

void loop()
{
  SCmd.readSerial();
}

void PingPong()
{
  Serial.print(Begin_of_Message);
  Serial.print("BOMB");
  Serial.print(End_of_Message);
}

void NTAG_Halt()
{
  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  Serial.print(Begin_of_Message);
  Serial.print("HALT");
  Serial.print(End_of_Message);
}

void NTAG_Here()
{
  Serial.print(Begin_of_Message);
  
  if(!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial())
    Serial.print("NO");
  else
    Serial.print("YES");

  Serial.print(End_of_Message);
}

void NTAG_UID()
{
  Serial.print(Begin_of_Message);
  for (byte i = 0; i < mfrc522.uid.size; i++)
  {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  } 
  Serial.print(End_of_Message);
}

void Read_Amiibo()
{
  char *arg;
  arg = SCmd.next(); 

  MFRC522::StatusCode status;
  byte buffer[18];
  byte size = sizeof(buffer);

  status = (MFRC522::StatusCode) mfrc522.MIFARE_Read(atoi(arg), buffer, &size);
  if (status != MFRC522::STATUS_OK) 
  {
      Serial.print(Begin_of_Message);
      Serial.print("/ERROR Data: ");
      Serial.print(mfrc522.GetStatusCodeName(status));
      Serial.print(End_of_Message);
  }
    
  Serial.print(Begin_of_Message);
  for (byte i = 0; i < 4; i++)
  {
    Serial.print(buffer[i] < 0x10 ? "0" : "");
    Serial.print(buffer[i], HEX);
  }
  Serial.print(End_of_Message);
}

/**
 * Authenticate with a NTAG216.
 * 
 * Only for NTAG216. First implemented by Gargantuanman.
 * 
 * @param[in]   passWord   password.
 * @param[in]   pACK       result success???.
 * @return STATUS_OK on success, STATUS_??? otherwise.
 */
MFRC522::StatusCode PCD_NTAG216_AUTH(byte* passWord, byte pACK[]) //Authenticate with 32bit password
{
  // TODO: Fix cmdBuffer length and rxlength. They really should match.
  //       (Better still, rxlength should not even be necessary.)

  MFRC522::StatusCode result;
  byte        cmdBuffer[18]; // We need room for 16 bytes data and 2 bytes CRC_A.
  
  cmdBuffer[0] = 0x1B; //Comando de autentificacion
  
  for (byte i = 0; i<4; i++)
    cmdBuffer[i+1] = passWord[i];
  
  result = mfrc522.PCD_CalculateCRC(cmdBuffer, 5, &cmdBuffer[5]);
  
  if (result!=MFRC522::STATUS_OK) {
    return result;
  }
  
  // Transceive the data, store the reply in cmdBuffer[]
  byte waitIRq    = 0x30; // RxIRq and IdleIRq
//  byte cmdBufferSize  = sizeof(cmdBuffer);
  byte validBits    = 0;
  byte rxlength   = 5;
  result = mfrc522.PCD_CommunicateWithPICC(MFRC522::PCD_Transceive, waitIRq, cmdBuffer, 7, cmdBuffer, &rxlength, &validBits);
  
  pACK[0] = cmdBuffer[0];
  pACK[1] = cmdBuffer[1];
  
  if (result!=MFRC522::STATUS_OK) {
    return result;
  }
  
  return MFRC522::STATUS_OK;
} // End PCD_NTAG216_AUTH()

byte authenticate()
{
    int uid[7];
    for (byte i = 0; i < 7; i++)
    {
        uid[i] = mfrc522.uid.uidByte[i];
    }
    byte password[4];
    password[0] = ((byte)(0xFF & (0xAA ^ (uid[1] ^ uid[3]))));
    password[1] = ((byte)(0xFF & (0x55 ^ (uid[2] ^ uid[4]))));
    password[2] = ((byte)(0xFF & (0xAA ^ (uid[3] ^ uid[5]))));
    password[3] = ((byte)(0xFF & (0x55 ^ (uid[4] ^ uid[6]))));
    byte resp[2];
    MFRC522::StatusCode status;
    status = (MFRC522::StatusCode)PCD_NTAG216_AUTH(password, resp);
    if (status != MFRC522::STATUS_OK)
    {
        Serial.print(Begin_of_Message);
        Serial.print("/ERROR Auth: ");
        Serial.print(mfrc522.GetStatusCodeName(status));
        Serial.print(End_of_Message);
        return 1;
    }
    return 0;
}

void Restore_Amiibo() {
    byte buffer[0x21C];

    Serial.print(Begin_of_Message);
    Serial.print("/WAIT");
    Serial.print(End_of_Message);

    while (Serial.available() == 0)
    {
    }

    Serial.readBytes(buffer, 0x21C);

    int authResult = authenticate();
    if (authResult == 1) {
        return;
    }

    MFRC522::StatusCode status;

    // Write Data
    for (byte page = 4; page < 135; page++)
    {
        if ((page >= 0xD && page < 0x20) || (page >= 130 && page < 133)) {
            continue;
        }
        status = (MFRC522::StatusCode)mfrc522.MIFARE_Ultralight_Write(page, buffer + (page * 4), 4);
        if (status != MFRC522::STATUS_OK)
        {
            Serial.print(Begin_of_Message);
            Serial.print("/ERROR Data: ");
            Serial.print(mfrc522.GetStatusCodeName(status));
            Serial.print(End_of_Message);
            break;
        }
    }

    if (status == MFRC522::STATUS_OK)
    {
        Serial.print(Begin_of_Message);
        Serial.print("/END_WRITE");
        Serial.print(End_of_Message);
    }
}

void Write_Amiibo()
{
  char *arg;
  arg = SCmd.next(); 

  byte buffer[0x21C];

  Serial.print(Begin_of_Message);
  Serial.print("/WAIT");
  Serial.print(End_of_Message);

  while(Serial.available() == 0){}

  Serial.readBytes(buffer, 0x21C); 

  MFRC522::StatusCode status;

  // Write Data
  for (byte page = 3; page < 135; page++)
  {
    status = (MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, buffer + (page * 4), 4);
    if (status != MFRC522::STATUS_OK)
    {
      Serial.print(Begin_of_Message);
      Serial.print("/ERROR Data: ");
      Serial.print(mfrc522.GetStatusCodeName(status));
      Serial.print(End_of_Message);
      break;
    }
  }

  if (atoi(arg) == 1)
  {
    if(status == MFRC522::STATUS_OK)
    {
      // Write Dynamic Lock Bytes
      byte Dynamic_Lock_Bytes[] = { 0x01, 0x00, 0x0F, 0xBD };
      status = (MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(130, Dynamic_Lock_Bytes, 4);
      if (status != MFRC522::STATUS_OK)
      {
        Serial.print(Begin_of_Message);
        Serial.print("/ERROR DynLock: ");
        Serial.print(mfrc522.GetStatusCodeName(status));
        Serial.print(End_of_Message);
      }
    }

    if(status == MFRC522::STATUS_OK)
    {
      // Write Static Lock Bytes
      byte Static_Lock_Bytes[] = { 0x0F, 0xE0, 0x0F, 0xE0 };
      status = (MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(2, Static_Lock_Bytes, 4);
      if (status != MFRC522::STATUS_OK)
      {
        Serial.print(Begin_of_Message);
        Serial.print("/ERROR StaticLock: ");
        Serial.print(mfrc522.GetStatusCodeName(status));
        Serial.print(End_of_Message);
      }
    }
  }

  if(status == MFRC522::STATUS_OK)
  {
    Serial.print(Begin_of_Message);
    Serial.print("/END_WRITE");
    Serial.print(End_of_Message);
  }
}
