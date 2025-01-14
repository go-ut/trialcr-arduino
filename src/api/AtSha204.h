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
#ifndef LIB_ATSHA204_H_
#define LIB_ATSHA204_H_

#include <Arduino.h>
#include "CryptoBuffer.h"
#include "../atsha204-atmel/sha204_comm_marshaling.h"


class AtSha204
{
public:
  AtSha204(uint8_t pin);
  AtSha204();
  ~AtSha204();

  CryptoBuffer rsp;
  uint8_t getRandom();
  uint8_t macBasic(uint8_t *to_mac, int len);
  uint8_t checkMacBasic(uint8_t *to_mac, int len, uint8_t *rsp);
  void enableDebug(Stream* stream);
  uint8_t read_zone(uint8_t zone, uint16_t address, uint8_t* zone_data);
  uint8_t configure_slots(void);
  uint8_t lock_config_zone(void);
  uint8_t lock_data_zone(void);
  uint8_t write_keys(void);
  uint8_t read_serial_number(uint8_t* tx_buffer, uint8_t* sn);
  uint8_t check_response_status(uint8_t ret_code, uint8_t* response);
  uint8_t getMacDigest(uint8_t* challenge, uint8_t* response_mac, uint8_t slot);
  //uint8_t getMcuDigest(uint8_t* privkey, uint8_t* challenge, uint8_t* serial_num_short, uint8_t* mcuMac);
  uint8_t deriveKeyClient(uint8_t slot, uint8_t* serialnum);
  uint8_t countZeroBits(uint8_t number);
  uint8_t status();
  uint8_t get_mating_cycles(uint32_t& count);
  uint8_t authenticate(void);
  uint8_t setUserData(char* userdata);
  uint8_t getUserData(char* userdata);
  uint8_t get_mating_limit(char* userdata);
  uint8_t set_mating_limit(char* userdata);
  uint8_t updateMonotonicCounter(void);
  void setSwiPorts(void);
  uint8_t authenticate_mac(AtSha204& hostTag);


protected:
  uint8_t command[SHA204_CMD_SIZE_MAX];
  uint8_t temp[SHA204_RSP_SIZE_MAX];
  uint8_t response_status[SHA204_RSP_SIZE_MIN];
  Stream *debugStream = NULL;
  volatile uint8_t* device_port_DDR_inst, * device_port_OUT_inst, * device_port_IN_inst;
  uint8_t device_pin_inst;

  void idle();


};



#endif
