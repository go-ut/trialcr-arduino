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


#define SHA204_KEY_ID1          (8)
#define SHA204_KEY_ID2          (7)
#define SHA204_KEY_PARENT       (3)
#define SHA204_KEY_CHILD        (6)

AtSha204::AtSha204(uint8_t pin)
{
  sha204p_set_device_id(pin);	
  sha204p_init();
}


AtSha204::~AtSha204() { }

void AtSha204::idle()
{
    sha204p_idle();
}

uint8_t AtSha204::getRandom()
{
  volatile uint8_t ret_code;

  uint8_t *random = &this->temp[SHA204_BUFFER_POS_DATA];

  sha204p_wakeup();

  ret_code = sha204m_random(this->command, this->temp, RANDOM_NO_SEED_UPDATE);
  if (ret_code == SHA204_SUCCESS)
    {
      this->rsp.copyBufferFrom(random, 32);
    }


  sha204p_idle();
  return ret_code;
}


void AtSha204::enableDebug(Stream* stream)
{
  this->debugStream = stream;
}



uint8_t AtSha204::read_config_zone(uint8_t* config_data)
{

	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	uint16_t config_address;

	// Make the command buffer the size of the Read command.
	uint8_t command[READ_COUNT];

	// Make the response buffer the size of the maximum Read response.
	uint8_t response[READ_32_RSP_SIZE];

	// Use this buffer to read the last 24 bytes in 4-byte junks.
	uint8_t response_read_4[READ_4_RSP_SIZE];

	uint8_t* p_response;


	// Read first 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	memset(response, 0, sizeof(response));
	config_address = 0;
	ret_code = sha204m_read(command, response, SHA204_ZONE_CONFIG | READ_ZONE_MODE_32_BYTES, config_address);	
	sha204p_sleep();	
	if (ret_code != SHA204_SUCCESS)
		return ret_code;
	

	if (config_data) {
		memcpy(config_data, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
		config_data += SHA204_ZONE_ACCESS_32;
	}
	// Read second 32 bytes. Put a breakpoint after the read and inspect "response" to obtain the data.

	
	memset(response, 0, sizeof(response));
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	config_address += SHA204_ZONE_ACCESS_32;
	memset(response, 0, sizeof(response));
	
	
	ret_code = sha204m_read(command, response, SHA204_ZONE_CONFIG | READ_ZONE_MODE_32_BYTES, config_address);
	
	sha204p_sleep();
	if (ret_code != SHA204_SUCCESS)
		return ret_code;


	if (config_data) {
		memcpy(config_data, &response[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_32);
		config_data += SHA204_ZONE_ACCESS_32;
	}
		

	// Read last 24 bytes in six four-byte junks.
	memset(response, 0, sizeof(response));
	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;	

	config_address += SHA204_ZONE_ACCESS_32;
	response[SHA204_BUFFER_POS_COUNT] = 0;
	p_response = &response[SHA204_BUFFER_POS_DATA];
	memset(response, 0, sizeof(response));
	while (config_address < SHA204_CONFIG_SIZE) {
		memset(response_read_4, 0, sizeof(response_read_4));
		ret_code = sha204m_read(command, response_read_4, SHA204_ZONE_CONFIG, config_address);
		if (ret_code != SHA204_SUCCESS) {
			sha204p_sleep();
			return ret_code;
		}
		memcpy(p_response, &response_read_4[SHA204_BUFFER_POS_DATA], SHA204_ZONE_ACCESS_4);
		p_response += SHA204_ZONE_ACCESS_4;
		response[SHA204_BUFFER_POS_COUNT] += SHA204_ZONE_ACCESS_4; // Update count byte in virtual response packet.
		config_address += SHA204_ZONE_ACCESS_4;
	}
	// Put a breakpoint here and inspect "response" to obtain the data.
	sha204p_sleep();

	if (ret_code == SHA204_SUCCESS && config_data)
		memcpy(config_data, &response[SHA204_BUFFER_POS_DATA], SHA204_CONFIG_SIZE - 2 * SHA204_ZONE_ACCESS_32);

	this->rsp.copyBufferFrom(config_data, SHA204_CONFIG_SIZE);

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

	const uint8_t config_address = 32;

	uint8_t config_slots0thru1[] = { 0x8F, 0x31, 0x8F, 0x32};
	uint8_t config_slots2thru3[] = { 0x8F, 0x8F, 0x9F, 0x8F};
	uint8_t config_slots6thru7[] = { 0xAF, 0x37, 0xAF, 0x38};
	uint8_t config_slot8[]	     = { 0x8F, 0x8F, 0x89, 0xF2 };

	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_SHORT];

	uint8_t data_load[SHA204_ZONE_ACCESS_4];

	// Make the response buffer the size of a Read response.
	uint8_t response[READ_4_RSP_SIZE];

	// Wake up the client device.

	ret_code = sha204c_wakeup(response);
	if (ret_code != SHA204_SUCCESS)
		return ret_code;

	// Write slots 0 through 1
	ret_code = sha204m_write(command, response, SHA204_ZONE_CONFIG, 20, config_slots0thru1, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Write slots 2 through 3
	ret_code = sha204m_write(command, response, SHA204_ZONE_CONFIG, 24, config_slots2thru3, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Write slots 6 through 7
	ret_code = sha204m_write(command, response, SHA204_ZONE_CONFIG, 32, config_slots6thru7, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
	}

	// Write slot8
	ret_code = sha204m_write(command, response,  SHA204_ZONE_CONFIG, 36, config_slot8, NULL);
	if (ret_code != SHA204_SUCCESS) {
		sha204p_sleep();
		return ret_code;
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

	sha204p_sleep();

	ret_code = this->read_config_zone(config_data);
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

uint8_t AtSha204::write_keys(void)
{
	// declared as "volatile" for easier debugging
	volatile uint8_t ret_code;

	const uint16_t data_address[] = { 0x0000, 0x0020, 0x0040, 0x0060, 0x00C0, 0x00E0, 0x0100 };

	uint8_t i = 0;

	uint8_t privkey[32] = {
		0x28, 0x68, 0x72, 0x3F, 0x67, 0x19, 0x01, 0x5E,
		0x49, 0x5C, 0x54, 0x3F, 0xAD, 0x5A, 0xE8, 0x70,
		0x42, 0xCD, 0x0F, 0x01, 0xF4, 0x30, 0xFD, 0x7C,
		0x8A, 0x00, 0x2C, 0x2D, 0x94, 0xEC, 0x66, 0x8C
	};

	// Make the command buffer the long size (32 bytes, no MAC) of the Write command.
	uint8_t command[WRITE_COUNT_LONG];


	// Make the response buffer the size of a Read response.
	uint8_t response[READ_32_RSP_SIZE];

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
uint8_t check_response_status(uint8_t ret_code, uint8_t* response)
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

uint8_t AtSha204::test(void)
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
	number every time we authenticate. The same nonce would produce the same MAC
	response. Be aware that the Random command returns a fixed number
	(0xFFFF0000FFFF0000...) when the configuration zone of the device is not locked.
	*/
	//sha204p_set_device_id(SHA204_HOST_ADDRESS);

	//Serial.println("here");

	
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




