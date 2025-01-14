/* -*- mode: c++; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of cryptoauth-arduino.
 *
 * cryptoauth-arduino is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * cryptoauth-arduino is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cryptoauth-arduino.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "AtSha204.h"
#include "../atsha204-atmel/sha204_physical.h"
#include "../atsha204-atmel/sha204_comm_marshaling.h"
#include "../atsha204-atmel/sha204_lib_return_codes.h"
#include "../atsha204-atmel/sha204_helper.h"
#include "../common-atmel/timer_utilities.h"
#include <string.h>
#include <arduino.h>
#include "../common-atmel/swi_phys.h"




#define CHAR_BIT      (8)  

#define SHA204_KEY_ID1          (8)
#define SHA204_KEY_ID2          (7)
#define SHA204_KEY_PARENT       (3)
#define SHA204_KEY_CHILD        (6)

#define USE_FLAG_SLOT6		(64)
#define USE_FLAG_SLOT7		(66)
#define UPDATE_COUNT_SLOT7  (67)

#define USER_DATA_START_ADDR (0x120)
#define MATING_LIMIT_START_ADDR (0x1E0)  


typedef struct
{
	uint8_t byte_address;
	uint8_t bytes[4];

} slot_pair;


const slot_pair smartid_slot_config[] = {

	{20, {0x8F, 0x31, 0x8F, 0x32} },  // slots 0 and 1
	{24, {0x8F, 0x8F, 0x9F, 0x8F} },  // slots 2 and 3
	{32, {0xAF, 0x37, 0xAF, 0x38} },  // slots 6 and 7
	{36, {0x8F, 0x8F, 0x0F, 0x00} },  // slots 8 and 9

	{40, {0x0F, 0x00, 0x0F, 0x00} },  // slots 10 and 11
	{44, {0x0F, 0x00, 0x0F, 0x00} },  // slots 12 and 13
	{48, {0x0F, 0x00, 0x0F, 0x00} }   // slots 14 and 15
};

AtSha204::AtSha204(uint8_t pin)
{
  
  sha204p_set_device_id(pin);	// tag development - pass in Arduino pin
  sha204p_init();

  /*uint8_t device_pin = 0;

  device_pin = digitalPinToBitMask(pin);	// Find the bit value of the pin
  uint8_t port = digitalPinToPort(pin);	// temoporarily used to get the next three registers

  // Point to data direction register port of pin
  device_port_DDR = portModeRegister(port);
  // Point to output register of pin
  device_port_OUT = portOutputRegister(port);
  // Point to input register of pin
  device_port_IN = portInputRegister(port);*/

  device_port_DDR_inst = device_port_DDR;
  device_port_OUT_inst = device_port_OUT;
  device_port_IN_inst = device_port_IN;
  device_pin_inst = device_pin;

}

AtSha204::~AtSha204() { }

void AtSha204::idle()
{
	setSwiPorts();

    sha204p_idle();
}

uint8_t AtSha204::getRandom()
{
  volatile uint8_t ret_code;

  uint8_t *random = &this->temp[SHA204_BUFFER_POS_DATA];

  setSwiPorts();

  sha204p_wakeup();

  ret_code = sha204m_random(this->command, this->temp, RANDOM_NO_SEED_UPDATE);
  if (ret_code != SHA204_SUCCESS)
  {
	  sha204p_sleep();
	  return ret_code;
  }

  this->rsp.copyBufferFrom(random, 32);


  return ret_code;
}


void AtSha204::enableDebug(Stream* stream)
{
  this->debugStream = stream;
}



uint8_t AtSha204::read_zone(uint8_t zone, uint16_t address, uint8_t* zone_data)
{

	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	//uint16_t config_address;

	// Make the command buffer the size of the Read command.
	uint8_t command[READ_COUNT];

	// Make the response buffer the size of the maximum Read response.
	uint8_t response[READ_32_RSP_SIZE];

	// Use this buffer to read the last 24 bytes in 4-byte junks.
	uint8_t response_read_4[READ_4_RSP_SIZE];

	uint8_t* p_response;

	setSwiPorts();	

	// Read first 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;


	memset(response, 0, sizeof(response));
	//config_address = 0;
	ret_code = sha204m_read(command, response, zone | READ_ZONE_MODE_32_BYTES, address);
	sha204p_sleep();	
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
	
	

	if (zone_data) {
		memcpy(zone_data, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
		zone_data += SHA204_ZONE_ACCESS_32;
	}
	// Read second 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.

	
	memset(response, 0, sizeof(response));
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	address += SHA204_ZONE_ACCESS_32;
	memset(response, 0, sizeof(response));
	
	
	ret_code = sha204m_read(command, response, zone | READ_ZONE_MODE_32_BYTES, address);
	
	sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;


	if (zone_data) {
		memcpy(zone_data, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
		zone_data += SHA204_ZONE_ACCESS_32;
	}
		

	// Read last 24 bytes in six four-byte junks.
	memset(response, 0, sizeof(response));
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;	

	address += SHA204_ZONE_ACCESS_32;
	response[SHA204_BUFFER_POS_COUNT] = 0;
	p_response = &response[SHA204_BUFFER_POS_DATA];
	memset(response, 0, sizeof(response));
	while (address < SHA204_CONFIG_SIZE) {
		memset(response_read_4, 0, sizeof(response_read_4));
		ret_code = sha204m_read(command, response_read_4, zone, address);
		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}
		memcpy(p_response, &response_read_4[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_4);
		p_response += SHA204_ZONE_ACCESS_4;
		response[SHA204_BUFFER_POS_COUNT] += SHA204_ZONE_ACCESS_4; // Update count byte in virtual response packet.
		address += SHA204_ZONE_ACCESS_4;
	}
	// Put a breakpoint here and inspect "response" to obtain the data.
	sha204p_sleep();

	if (ret_code == SHA204_SUCCESS && zone_data)
		memcpy(zone_data, &response[SHA204_BUFFER_POS_DATA], SHA204_CONFIG_SIZE - 2 * SHA204_ZONE_ACCESS_32);

	this->rsp.copyBufferFrom(zone_data, SHA204_CONFIG_SIZE);


	return ret_code;



}


/** \brief This function configures slots for keys
 *
*/
uint8_t AtSha204::configure_slots(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;
	int i = 0;

	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_SHORT];

	uint8_t data_load[SHA204_ZONE_ACCESS_4];

	// Make the response buffer the size of a Read response.
	uint8_t response[READ_4_RSP_SIZE];

	setSwiPorts();

	// Wake up the client device.
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	for (i = 0; i < sizeof(smartid_slot_config) / sizeof(smartid_slot_config[0]); i++) 
	{

		ret_code = sha204m_write(command, response, SHA204_ZONE_CONFIG, smartid_slot_config[i].byte_address, smartid_slot_config[i].bytes, NULL);
		//Serial.println(ret_code);
		if (ret_code != SHA204_SUCCESS) {			
			sha204p_sleep();
			return ret_code;
		}

	}

	sha204p_sleep();

	return ret_code;
}

/** \brief This function locks configuration zone
	It first reads it and calculates the CRC of its content.
	It then sends a Lock command to the device.

	This function is disabled by default with the
	\ref SHA204_EXAMPLE_CONFIG_WITH_LOCK switch.

	Once the configuration zone is locked, the Random
	command returns a number from its high quality random
	number generator instead of a 0xFFFF0000FFFF0000...
	sequence.

	\param[in] device_id which device to lock
	\return status of the operation
*/
uint8_t AtSha204::lock_config_zone(void)
{

	uint8_t ret_code;
	uint8_t config_data[SHA204_CONFIG_SIZE];
	uint8_t crc_array[SHA204_CRC_SIZE];
	uint16_t crc;
	uint8_t command[LOCK_COUNT];
	uint8_t response[LOCK_RSP_SIZE];

	setSwiPorts();

	sha204p_sleep();

	ret_code = this->read_zone(SHA204_ZONE_CONFIG, 0, config_data);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Check whether the configuration zone is locked already.
	if (config_data[87] == 0)
		return ret_code;

	sha204c_calculate_crc(sizeof(config_data), config_data, crc_array);
	crc = (crc_array[1] << 8) + crc_array[0];

	ret_code = sha204c_wakeup(response);
	ret_code = sha204m_lock(command, response, SHA204_ZONE_CONFIG, crc);

	return ret_code;


}


/** \brief This function locks data zone
*/
uint8_t AtSha204::lock_data_zone(void)
{

	uint8_t ret_code;
	uint8_t config_data[SHA204_CONFIG_SIZE];
	uint8_t crc_array[SHA204_CRC_SIZE];
	uint16_t crc;
	uint8_t command[LOCK_COUNT];
	uint8_t response[LOCK_RSP_SIZE];

	setSwiPorts();

	sha204p_sleep();

	ret_code = this->read_zone(SHA204_ZONE_CONFIG, 0, config_data);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Check whether the data zone is locked already.
	if (config_data[86] == 0)
		return ret_code;

	sha204c_calculate_crc(sizeof(config_data), config_data, crc_array);
	crc = (crc_array[1] << 8) + crc_array[0];

	ret_code = sha204c_wakeup(response);
	ret_code = sha204m_lock(command, response, SHA204_ZONE_OTP | LOCK_ZONE_NO_CRC, 0x00);

	return ret_code;


}

uint8_t AtSha204::write_keys(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	const uint16_t data_address[] = { 0x0000, 0x0020, 0x0040, 0x0060, 0x00C0, 0x00E0, 0x0100 };

	uint8_t i = 0;

	static const uint8_t PROGMEM privkey[32]  = {
		0x28, 0x68, 0x72, 0x3F, 0x67, 0x19, 0x01, 0x5E,
		0x49, 0x5C, 0x54, 0x3F, 0xAD, 0x5A, 0xE8, 0x70,
		0x42, 0xCD, 0x0F, 0x01, 0xF4, 0x30, 0xFD, 0x7C,
		0x8A, 0x00, 0x2C, 0x2D, 0x94, 0xEC, 0x66, 0x8C
	};

	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_LONG];


	// Make the response buffer the size of a Read response.
	uint8_t response[READ_32_RSP_SIZE];

	setSwiPorts();

	// wakeup device
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Write keys
	for (i = 0; i < sizeof(data_address)/sizeof(data_address[0]); i++)
	{

		ret_code = sha204m_write(command, response, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, data_address[i], privkey, NULL);
		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}

	}
	

	sha204p_sleep();

	return ret_code;
}


/** \brief This function reads the serial number from the device.
 *
		   The serial number is stored in bytes 0 to 3 and 8 to 12
		   of the configuration zone.
   \param[in] tx_buffer pointer to transmit buffer.
	\param[out] sn pointer to nine-byte serial number
	\return status of the operation
*/
uint8_t AtSha204::read_serial_number(uint8_t* tx_buffer, uint8_t* sn)
{
	uint8_t rx_buffer[READ_32_RSP_SIZE];

	uint8_t status = sha204m_read(tx_buffer, rx_buffer,
		SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_CONFIG, 0);

	setSwiPorts();

	if (status != SHA204_SUCCESS)
		sha204p_sleep();

	memcpy(sn, &rx_buffer[SHA204_BUFFER_POS_DATA], 4);
	memcpy(sn + 4, &rx_buffer[SHA204_BUFFER_POS_DATA + 8], 5);

	return status;
}


/** \brief This function checks the response status byte and puts the device
		   to sleep if there was an error.
   \param[in] ret_code return code of function
	\param[in] response pointer to response buffer
	\return status of the operation
*/
uint8_t AtSha204::check_response_status(uint8_t ret_code, uint8_t* response)
{
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	ret_code = response[SHA204_BUFFER_POS_STATUS];
	if (ret_code != SHA204_SUCCESS)
		sha204p_sleep();

	return ret_code;
}


/** \brief This function serves as an authentication example using the ATSHA204 Read and
 *         MAC commands for a client, and the Nonce, GenDig, and CheckMac commands for
 *         a host device.

Creating a diversified key on the client using its serial number allows a host device to
check a MAC using a root key on devices with different diversified keys. The host device
can calculate the diversified key by using a root key and the serial number of the client.

Brief explanation for this command sequence:\n
During personalization, a key is derived from a root key residing in the host, and the
serial number of the client. The host reads the serial number of the client, pads it with
zeros, and stores it in its TempKey. It then executes a GenDig command that hashes the
root key and the TempKey, a.o. Now, when the client receives a MAC command with the
child key id, a CheckMac command on the host using the TempKey will succeed.

To run this command sequence successfully the host device has to be configured first:
The parent key has to be flagged as CheckOnly and the child key has to point to the parent key.

Use the following sequence for secure authentication using the default configuration for
the host device and modifying the default configuration for the client. (This function does
this for you by calling \ref sha204e_configure_diversify_key.)
<ul>
<li>
	Point slot 10 (child key) to key id 13 (parent key) by changing the default from 0x7A
	(parent key = 10, roll key operation) to 0x7D (parent key = 13).
</li>
<li>
	Reset the CheckOnly flag in key 13 by changing the default from 0xDD to 0xCD.
</li>
</ul>

Command sequence when using a diversified key:
<ol>
<li>
	MCU to client device: Read serial number (Read command, zone = config, address = 0).
</li>
<li>
	MCU to host device:   Get random number (Random command).
</li>
<li>
	MCU to host device:   Pad serial number with zeros and store it in TempKey
						  (Nonce command, mode = pass-through).
</li>
<li>
	MCU to host device:   GenDig -> Host TempKey now holds child key
									(GenDig command, other data = DeriveKey command).
</li>
<li>
	MCU to client device: MAC ->
	response = sha256(child key, challenge = random, MAC command, 3 bytes of SN)
</li>
<li>
	MCU to host device:   CheckMac ->
	sha256(TempKey = child key, challenge = random = provided, MAC command, 3 bytes of SN)
</li>
</ol>

 * \return status of the operation
 */





/*uint8_t AtSha204::test(void)
{
	uint8_t privkey[32] = {
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
	};

	uint8_t divkey[32] = {
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
	};

	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	sha204h_temp_key tempkey_mac;

	// Make the command buffer the maximum command size.
	uint8_t command[SHA204_CMD_SIZE_MAX];

	// padded serial number (9 bytes + 23 zeros)
	uint8_t serial_number[NONCE_NUMIN_SIZE_PASSTHROUGH];

	// random number - is used as the MAC challenge
	uint8_t response_random[RANDOM_RSP_SIZE];
	uint8_t* random_number = &response_random[SHA204_BUFFER_POS_DATA];

	// DeriveKey command.
	// This command was used during configuration (personalization) to 
	// diversify the root key with the serial number of the client.
	uint8_t derive_key_command[] = { 0x1C, 0x04, 0x0A, 0x00 };

	// Make the status response buffer the size of a status response.
	uint8_t response_status[SHA204_RSP_SIZE_MIN];

	// MAC response buffer
	uint8_t response_mac[SHA204_RSP_SIZE_MAX];

	// We need this buffer for the CheckMac command.
	uint8_t checkmac_other_data[CHECKMAC_OTHER_DATA_SIZE];

	// jjh: added
	struct sha204h_nonce_in_out nonce_param;	   //parameter for nonce helper function
	struct sha204h_temp_key tempkey;			      //tempkey parameter for nonce and mac helper function
	static uint8_t wakeup_response[SHA204_RSP_SIZE_MIN];
	static uint8_t tx_buffer[CHECKMAC_COUNT];
	static uint8_t rx_buffer[MAC_RSP_SIZE];
	struct sha204h_gen_dig_in_out gendig_param;	//parameter for gendig helper function
	struct sha204h_temp_key tempkey2;			      //tempkey parameter for nonce and mac helper function

	struct sha204h_mac_in_out mac_param;		   //parameter for mac helper function

	uint8_t command_derive_key[GENDIG_OTHER_DATA_SIZE];

	static uint8_t mac_stuff[CHECKMAC_CLIENT_RESPONSE_SIZE];

	uint8_t serial_num_mac[9] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	uint8_t x = 0;

	memset(serial_number, 0, sizeof(serial_number));
	ret_code = read_serial_number(command, serial_number);

	serial_number[0] = 0x01;
	serial_number[1] = 0x23;
	serial_number[2] = 0xAB;
	serial_number[3] = 0xA3;
	serial_number[4] = 0xFF;
	serial_number[5] = 0x60;
	serial_number[6] = 0x24;
	serial_number[7] = 0x76;
	serial_number[8] = 0xEE;

	uint8_t printbreak = 3;

	uint8_t challenge[32];


	uint8_t otp[11] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };


	// Calculate TempKey using helper function.
	nonce_param.mode = NONCE_MODE_PASSTHROUGH;  // jjh: changed
	nonce_param.num_in = serial_number;
	nonce_param.rand_out = NULL; //&rx_buffer[SHA204_BUFFER_POS_DATA];
	nonce_param.temp_key = &tempkey;
	ret_code = sha204h_nonce(&nonce_param);

	// ----------------------- GenDig --------------------------------------------

	// Update TempKey using helper function.
	gendig_param.zone = GENDIG_ZONE_DATA;
	gendig_param.key_id = SHA204_KEY_ID1;
	gendig_param.stored_value = privkey;
	gendig_param.temp_key = &tempkey;

	command_derive_key[0] = 0x1C;
	command_derive_key[1] = 0x04;
	command_derive_key[2] = 0x07;
	command_derive_key[3] = 0x00;

	ret_code = sha204h_gen_dig_other(&gendig_param, command_derive_key);


	memcpy(divkey, &tempkey.value, 32);


	// Calculate TempKey using helper function.
	nonce_param.mode = NONCE_MODE_PASSTHROUGH;  // jjh: changed
	nonce_param.num_in = serial_number;
	nonce_param.rand_out = NULL; //&rx_buffer[SHA204_BUFFER_POS_DATA];
	nonce_param.temp_key = &tempkey;
	ret_code = sha204h_nonce(&nonce_param);


	// do it again: 
	gendig_param.zone = GENDIG_ZONE_DATA;
	gendig_param.key_id = SHA204_KEY_ID2;
	gendig_param.stored_value = divkey;
	gendig_param.temp_key = &tempkey;

	command_derive_key[0] = 0x1C;
	command_derive_key[1] = 0x04;
	command_derive_key[2] = 0x06;
	command_derive_key[3] = 0x00;

	ret_code = sha204h_gen_dig_other(&gendig_param, command_derive_key);


	memcpy(divkey, &tempkey.value, 32);

	// normally this would come from random number generation
	memset(challenge, 0x11, 32);

	// Calculate MAC using helper function.
	mac_param.mode = MAC_MODE_CHALLENGE;// | MAC_MODE_INCLUDE_SN;
	mac_param.key_id = 0x0006;
	mac_param.challenge = challenge;
	mac_param.key = divkey;  //tbd
	mac_param.otp = otp; 
	mac_param.sn = serial_num_mac; 
	mac_param.response = mac_stuff;
	mac_param.temp_key = &tempkey_mac;

	ret_code = sha204h_mac(&mac_param);


	printbreak = 3;
	Serial.println("\nMAC response");
	for (x = 0; x < 32; x++) {
		if (mac_stuff[x] <= 0x0F) {
			Serial.print("0");
		}
		Serial.print(mac_stuff[x], HEX);
		Serial.print(" ");
		if (x == printbreak) {
			Serial.println(" ");
			printbreak += 4;
		}

	}

	return ret_code;

}
*/

uint8_t AtSha204::getMacDigest(uint8_t *challenge, uint8_t *response_mac, uint8_t slot)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	// Make the command buffer the maximum command size.
	uint8_t command[SHA204_CMD_SIZE_MAX];

	setSwiPorts();

	sha204p_wakeup();

	
	ret_code = sha204m_mac(command, response_mac, MAC_MODE_CHALLENGE, slot, challenge);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_sleep();

	return ret_code;


}

uint8_t AtSha204::deriveKeyClient(uint8_t slot, uint8_t *serialnum)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	setSwiPorts();

	sha204p_wakeup();	

	// Send Nonce command in pass-through mode using the random number in preparation
	// for DeriveKey command. TempKey holds the random number after this command succeeded.
	ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, serialnum); 
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_idle();

	// Send DeriveKey command.
	// child key = sha256(parent key[32], DeriveKey command[4], sn[3], 0[25], TempKey[32] = random)
	ret_code = sha204m_derive_key(command, response_status, DERIVE_KEY_RANDOM_FLAG, slot, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_sleep();

	return ret_code;


}


/*
uint8_t AtSha204::getMcuDigest(uint8_t* privkey, uint8_t* challenge, uint8_t* serial_num_short, uint8_t *mcuMac)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;
	int x = 0;


	uint8_t divkey[32] = {
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33
	};


	sha204h_temp_key tempkey_mac;

	// padded serial number (9 bytes + 23 zeros)
	uint8_t pad_serial_number[NONCE_NUMIN_SIZE_PASSTHROUGH];

	struct sha204h_nonce_in_out nonce_param;			//parameter for nonce helper function
	struct sha204h_temp_key tempkey;					//tempkey parameter for nonce and mac helper function
	struct sha204h_gen_dig_in_out gendig_param;			//parameter for gendig helper function

	struct sha204h_mac_in_out mac_param;				//parameter for mac helper function

	uint8_t command_derive_key[GENDIG_OTHER_DATA_SIZE] = { 0x1C, 0x04, 0x07, 0x00 };


	//uint8_t x = 0;

	uint8_t otp[11] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	

	memset(pad_serial_number, 0, NONCE_NUMIN_SIZE_PASSTHROUGH);
	memcpy(pad_serial_number, serial_num_short, 9);

	//for (x = 0; x < 32; x++) {

	//	Serial.print(pad_serial_number[x], HEX);

	//}


	// Calculate TempKey using helper function.
	nonce_param.mode = NONCE_MODE_PASSTHROUGH;  // jjh: changed
	nonce_param.num_in = pad_serial_number;
	nonce_param.rand_out = NULL; //&rx_buffer[SHA204_BUFFER_POS_DATA];
	nonce_param.temp_key = &tempkey;
	ret_code = sha204h_nonce(&nonce_param);	

	// ----------------------- GenDig --------------------------------------------

	// Update TempKey using helper function.
	gendig_param.zone = GENDIG_ZONE_DATA;
	gendig_param.key_id = SHA204_KEY_ID1;
	gendig_param.stored_value = privkey;
	gendig_param.temp_key = &tempkey;

	ret_code = sha204h_gen_dig_other(&gendig_param, command_derive_key);


	memcpy(divkey, &tempkey.value, 32);

	// Calculate TempKey using helper function.
	nonce_param.mode = NONCE_MODE_PASSTHROUGH;  // jjh: changed
	nonce_param.num_in = pad_serial_number;
	nonce_param.rand_out = NULL; 
	nonce_param.temp_key = &tempkey;
	ret_code = sha204h_nonce(&nonce_param);


	// do it again: 
	gendig_param.zone = GENDIG_ZONE_DATA;
	gendig_param.key_id = SHA204_KEY_ID2;
	gendig_param.stored_value = divkey;
	gendig_param.temp_key = &tempkey;

	command_derive_key[2] = 0x06;

	ret_code = sha204h_gen_dig_other(&gendig_param, command_derive_key);

	memcpy(divkey, &tempkey.value, 32);

	memset(mac_param.sn, 0x00, 9);

	// Calculate MAC using helper function.
	mac_param.mode = MAC_MODE_CHALLENGE;
	mac_param.key_id = 0x0006;
	mac_param.challenge = challenge;
	mac_param.key = divkey;  
	mac_param.otp = otp;
	//mac_param.sn = serial_num_short;
	mac_param.response = mcuMac;
	mac_param.temp_key = &tempkey_mac;

	// TBD: jjh
	ret_code = sha204h_mac(&mac_param);

	return ret_code;


}

*/

uint8_t AtSha204::countZeroBits(uint8_t number)
{
	size_t num_zeroes = 0;

	for (size_t i = 0; i < CHAR_BIT * sizeof(number); ++i)
	{
		if ((number & (1 << i)) == 0)
			++num_zeroes;
	}

	return num_zeroes;
}

uint8_t AtSha204::status()
{
	uint8_t sn[9];

	setSwiPorts();

	// First attempt to wakeup tag
	uint8_t returnCode = sha204p_wakeup();

	if (returnCode != SHA204_SUCCESS)
		goto Finalize;	

	// Read serial number	
	returnCode = read_serial_number(command, sn);

	if (returnCode != SHA204_SUCCESS)
		goto Finalize;

	sha204p_sleep();

	// Check device family
	if (sn[0] != 0x01 || sn[1] != 0x23 || sn[8] != 0xEE)
	{
		returnCode = SHA204_INVALID_SN;
		goto Finalize;
	}

Finalize:
	return returnCode;
}

//n = 2   #auths = C1 + 8C2 + 64(UpdateCount2)
uint8_t AtSha204::get_mating_cycles(uint32_t& count)
{
	uint8_t ret_code;
	uint8_t config_data[SHA204_CONFIG_SIZE];

	setSwiPorts();

	sha204p_sleep();

	ret_code = this->read_zone(SHA204_ZONE_CONFIG, 0, config_data);
	if (ret_code != SHA204_SUCCESS)
	{
		count = 0xFFFFFFFF;
		return ret_code;
	}

	// See Atmel-8863-CryptoAuth-Authentication-Counting-ApplicationNote.pdf (Section 2.3)
	count = countZeroBits(config_data[USE_FLAG_SLOT6]) + (8 * countZeroBits(config_data[USE_FLAG_SLOT7])) +
		(64 * config_data[UPDATE_COUNT_SLOT7]);

	return ret_code;
}


uint8_t AtSha204::authenticate(void)
{
	uint8_t ret_code;

	setSwiPorts();

	ret_code = sha204p_wakeup();

	// **This is currently what is doing authentication since I couldn't get digests to match**
	ret_code = this->status();


	return ret_code;
}


uint8_t AtSha204::setUserData(char* userdata)
{
	uint8_t ret_code;
	uint8_t i;
	char strSlotString[32];
	uint16_t numIterations;


	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_LONG];

	// Make the response buffer the size of a Read response.
	uint8_t response[READ_32_RSP_SIZE];

	uint16_t userDataLen;
	uint16_t remainder;

	setSwiPorts();

	// wakeup device
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	userDataLen = strlen(userdata);
	remainder = userDataLen % 32;

	numIterations = (remainder == 0) ? userDataLen / 32 : userDataLen / 32 + 1;	

	// Write to unused slots
	for (i = 0; i < numIterations; i++)
	{
		memcpy(strSlotString, userdata + (i * 32), 32);			

		// Last iteration we need to put terminator in correct location
		if (i == (numIterations - 1))
		{
			if (remainder == 0)
			{
				strSlotString[0] = '\0';
			}
			else
			{
				strSlotString[remainder] = '\0';
			}
		}

		ret_code = sha204m_write(command, response, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, USER_DATA_START_ADDR + i * 32, (uint8_t *) strSlotString, NULL);
		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}		

	}

	sha204p_sleep();

	return ret_code;
}


uint8_t AtSha204::getUserData(char* userdata)
{
	uint8_t ret_code;

	// Make the command buffer the size of the Read command.
	uint8_t command[READ_COUNT];

	// Make the response buffer the size of the maximum Read response.
	uint8_t response[READ_32_RSP_SIZE];

	uint16_t address = 0x0120;

	uint8_t finished = 0;
	uint8_t j, found;

	setSwiPorts();

	do
	{
		found = 0;

		ret_code = sha204c_wakeup(response);
		if (ret_code != SHA204_SUCCESS)
			return ret_code;

		memset(response, 0, sizeof(response));
		ret_code = sha204m_read(command, response, SHA204_ZONE_DATA | READ_ZONE_MODE_32_BYTES, address);
		sha204p_sleep();
		if (ret_code != SHA204_SUCCESS)
			return ret_code;

		if (userdata) {

			for (j = 0; j < 32; j++)
			{
				if (response[j] == 0)
				{
					found = 1;
					break;
				}

			}
	
			if (found)
			{
				// found termination character
				memcpy(userdata, &response[SHA204_BUFFER_POS_DATA], j + 1);
				finished = 1;
			}
			else
			{
				// did not find termination character
				memcpy(userdata, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
				userdata += SHA204_ZONE_ACCESS_32;
			}

		}
		else
		{
			finished = 1;
		}

		address += 32;

	} while (!finished);
		


	sha204p_sleep();

	return ret_code;
}


uint8_t AtSha204::get_mating_limit(char* userdata)
{
	uint8_t ret_code;

	// Make the command buffer the size of the Read command.
	uint8_t command[READ_COUNT];

	// Make the response buffer the size of the maximum Read response.
	uint8_t response[READ_32_RSP_SIZE];

	uint16_t address = 0x01E0;  

	uint8_t finished = 0;
	uint8_t j, found;

	setSwiPorts();

	
	found = 0;

	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	memset(response, 0, sizeof(response));
	ret_code = sha204m_read(command, response, SHA204_ZONE_DATA | READ_ZONE_MODE_32_BYTES, address);
	sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	if (userdata) 
	{

		for (j = 0; j < 32; j++)
		{
			if (response[j] == 0)
			{
				found = 1;
				break;
			}

		}

		if (found)
		{
			// found termination character
			memcpy(userdata, &response[SHA204_BUFFER_POS_DATA], j + 1);
			finished = 1;
		}

	}
	else
	{
		finished = 1;
	}

	sha204p_sleep();


	return ret_code;
}

uint8_t AtSha204::set_mating_limit(char* userdata)
{
	uint8_t ret_code;
	uint8_t i;

	uint16_t userDataLen;
	uint16_t remainder;
	char strSlotString[32];


	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_LONG];

	// Make the response buffer the size of a Read response.
	uint8_t response[READ_32_RSP_SIZE];


	setSwiPorts();

	userDataLen = strlen(userdata);
	remainder = userDataLen % 32;

	// wakeup device
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;


	memcpy(strSlotString, userdata + (i * 32), 32);

	if (remainder == 0)
	{
		strSlotString[0] = '\0';
	}
	else
	{
		strSlotString[remainder] = '\0';
	}
	

	ret_code = sha204m_write(command, response, SHA204_ZONE_COUNT_FLAG | SHA204_ZONE_DATA, MATING_LIMIT_START_ADDR, (uint8_t*)strSlotString , NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_sleep();

	return ret_code;
}



void AtSha204::setSwiPorts(void)
{
	device_port_DDR = device_port_DDR_inst;
	device_port_OUT = device_port_OUT_inst;
	device_port_IN = device_port_IN_inst;
	device_pin = device_pin_inst;
}

uint8_t AtSha204::updateMonotonicCounter(void)
{
	uint8_t ret_code;
	uint8_t serialNumber[9];

	static uint8_t randomnumber[32] = { 0x71, 0xE2, 0x34, 0xF3, 0xDF, 0xD4, 0x51, 0x3B,
							  0x6E, 0x83, 0x6D, 0xF4, 0xC7, 0xBD, 0xC2, 0x1B,
							  0xD6, 0xE2, 0xF5, 0xA7, 0x92, 0x2C, 0x64, 0xB0,
							  0x25, 0x57, 0x15, 0xC1, 0x04, 0x49, 0xA2, 0xD0 };

	uint8_t config_data[SHA204_CONFIG_SIZE];
	static uint8_t responseClientMac[SHA204_RSP_SIZE_MAX];

	setSwiPorts();

	ret_code = sha204p_wakeup();	


	ret_code = this->read_serial_number(command, serialNumber);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	

	// This will update slot counter(s)
	ret_code = this->getMacDigest(randomnumber, responseClientMac, SHA204_KEY_CHILD);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	

	ret_code = sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
	{
		sha204p_sleep();
		return ret_code;
	}

	/* Send DeriveKey commands (if necessary) */
	ret_code = this->read_zone(SHA204_ZONE_CONFIG, 0, config_data);
	if (ret_code != SHA204_SUCCESS)
	{
		sha204p_sleep();
		return ret_code;
	}

	if (config_data[USE_FLAG_SLOT6] == 0)
	{
		ret_code = this->deriveKeyClient(6, serialNumber);

		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}
	}

	ret_code = sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
	{
		sha204p_sleep();
		return ret_code;
	}

	ret_code = this->read_zone(SHA204_ZONE_CONFIG, 0, config_data);
	if (ret_code != SHA204_SUCCESS)
	{
		sha204p_sleep();
		return ret_code;
	}

	if (config_data[USE_FLAG_SLOT7] == 0)
	{
		ret_code = this->deriveKeyClient(7, serialNumber);

		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}
	}

	sha204p_sleep();	

	return ret_code;
}


uint8_t AtSha204::authenticate_mac(AtSha204& hostTag)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	static uint8_t response_random[RANDOM_RSP_SIZE];
	uint8_t* random = &response_random[SHA204_BUFFER_POS_DATA];

	// Make the command buffer the minimum size of the Write command.
	uint8_t command[SHA204_CMD_SIZE_MAX];

	// Make the response buffer the maximum size.
	uint8_t response_status[SHA204_RSP_SIZE_MIN];

	// MAC response buffer
	uint8_t response_mac[SHA204_RSP_SIZE_MAX];

	// We need this buffer for the DeriveKey, GenDig, and CheckMac command.
	uint8_t other_data[CHECKMAC_OTHER_DATA_SIZE];

	uint8_t command_derive_key[GENDIG_OTHER_DATA_SIZE];

	uint8_t command_mac[CHECKMAC_CLIENT_COMMAND_SIZE];

	// Initialize the hardware interface.
	// Depending on which interface you have linked the
	// library to, it initializes SWI GPIO, or I2C.
	// This example does not run when SWI UART is used.
	//sha204p_init();

	//ret_code = sha204e_configure_derive_key();
	//if (ret_code != SHA204_SUCCESS)
	//	return ret_code;
	
	/*
	Obtain a random number from host device. We can generate a random number to
	be used by a pass-through nonce (TempKey.SourceFlag = Input = 1) in whatever
	way we want but we use the host	device because it has a high-quality random
	number generator. We are using the host and not the client device because we
	like to show a typical accessory authentication example where the MCU this
	code is running on and the host device are inaccessible to an adversary,
	whereas the client device is built into an easily accessible accessory. We
	prevent an adversary to	mount replay attacks by supplying the pass-through
	nonce. For the same reason, we do not want to use the same pass-through
	number every time we authenticate. The same nonce would produce the same Mac
	response. Be aware that the Random command returns a fixed number
	(0xFFFF0000FFFF0000...) when the configuration zone of the device is not locked.
	*/

	//sha204p_set_device_id(SHA204_HOST_ADDRESS);
	hostTag.setSwiPorts();


	ret_code = sha204c_wakeup(response_status);
	//if (ret_code != SHA204_SUCCESS)
	//	return ret_code;
	

	// ---------------------------------------------------------------------------
	// host: Get random number.
	// No need to update the seed because it gets updated with every wake / sleep
	// cycle anyway.
	// ---------------------------------------------------------------------------
	ret_code = sha204m_random(command, response_random, RANDOM_NO_SEED_UPDATE);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		Serial.println(ret_code);
		return ret_code;
	}

	

	// ---------------------------------------------------------------------------
	// client: Create child key using a random pass-through nonce. 
	// Then send a MAC command using the same nonce.
	// ---------------------------------------------------------------------------
	//sha204p_set_device_id(SHA204_CLIENT_ADDRESS);
	this->setSwiPorts();

	// Send Nonce command in pass-through mode using the random number in preparation
	// for DeriveKey command. TempKey holds the random number after this command succeeded.
	/*ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, random);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Send DeriveKey command.
	// child key = sha256(parent key[32], DeriveKey command[4], sn[3], 0[25], TempKey[32] = random)
	ret_code = sha204m_derive_key(command, response_status, DERIVE_KEY_RANDOM_FLAG, SHA204_KEY_CHILD, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204e_sleep();
		return ret_code;
	}*/

	// Copy op-code and parameters to command_derive_key to be used in subsequent GenDig and CheckMac
	// host commands.
	memcpy(command_derive_key, &command[SHA204_OPCODE_IDX], sizeof(command_derive_key));

	// Send Nonce command in preparation for MAC command.
	ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, random);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_idle();

	// Send MAC command.
	// MAC = sha256(child key[32], TempKey[32] = random, MAC command[4], 0[11], sn8[1], 0[4], sn0_1[2], 0[2])
	// mode: first 32 bytes data slot (= child key), second 32 bytes TempKey (= random), TempKey.SourceFlag = Input
	ret_code = sha204m_mac(command, response_mac, MAC_MODE_BLOCK2_TEMPKEY | MAC_MODE_SOURCE_FLAG_MATCH,
		2 /*TBD*/, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Save op-code and parameters to be used in the CheckMac command for the host.
	memcpy(command_mac, &command[SHA204_OPCODE_IDX], sizeof(command_mac));

	// Put client device to sleep.
	sha204p_sleep();

	// ---------------------------------------------------------------------------
	// host: Generate digest (GenDig) using a random pass-through nonce.
	// Then send a CheckMac command with the MAC response.
	// ---------------------------------------------------------------------------

	// Send Nonce command in pass-through mode using the random number in preparation
	// for GenDig command. TempKey holds the random number after this command succeeded.
	//sha204p_set_device_id(SHA204_HOST_ADDRESS);

	ret_code = sha204c_wakeup(response_status);
	//if (ret_code != SHA204_SUCCESS)
	//	return ret_code;

	hostTag.setSwiPorts();

	ret_code = sha204m_nonce(command, response_status, NONCE_MODE_PASSTHROUGH, random);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	sha204p_idle();

	// Send GenDig command. TempKey holds the child key of the client after this command succeeded.
	// TempKey (= child key) = sha256(parent key[32], DeriveKey command[4], sn[3], 0[25], TempKey[32] = random)
	/*ret_code = sha204m_gen_dig(command, response_status, GENDIG_ZONE_DATA, SHA204_KEY_PARENT, command_derive_key);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}
	*/
	// Send CheckMac command.
	// CheckMac = sha256(TempKey[32] = child key, random[32], Mac command[4], 0[11], sn8[1], 0[4], sn0_1[2], 0[2])
	// mode: first 32 bytes TempKey (= child key), second 32 bytes client challenge (= random), TempKey.SourceFlag = Input
	// TempKey = child key -> CheckMac = MAC
	// Copy MAC command bytes (op-code, param1, param2) to other_data.
	memset(other_data, 0, sizeof(other_data));
	memcpy(other_data, command_mac, sizeof(command_mac));
	//ret_code = sha204m_check_mac(command, response_status, CHECKMAC_MODE_BLOCK1_TEMPKEY| CHECKMAC_MODE_SOURCE_FLAG_MATCH,
	//	2 /*TBD*/, random, &response_mac[SHA204_BUFFER_POS_DATA], other_data);

	ret_code = sha204m_check_mac(command, response_status, CHECKMAC_MODE_BLOCK2_TEMPKEY | CHECKMAC_MODE_SOURCE_FLAG_MATCH,
			2 /*TBD*/, random, &response_mac[SHA204_BUFFER_POS_DATA], other_data);

	sha204p_sleep();	

	ret_code = this->check_response_status(ret_code, response_status);

	Serial.println(ret_code);

	return ret_code;
}

