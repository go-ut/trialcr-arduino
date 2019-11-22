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
#include "../atecc108-atmel/ecc108_physical.h"
#include "../atecc108-atmel/ecc108_comm.h"

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
  uint8_t read_config_zone(uint8_t* config_data);
  uint8_t configure_slots(void);
  uint8_t lock_config_zone(void);
  uint8_t write_keys(void);
  uint8_t read_serial_number(uint8_t* tx_buffer, uint8_t* sn);
  uint8_t check_response_status(uint8_t ret_code, uint8_t* response);
  uint8_t test(void);


protected:
  uint8_t command[SHA204_CMD_SIZE_MAX];
  uint8_t temp[SHA204_RSP_SIZE_MAX];
  Stream *debugStream = NULL;
  void idle();


};



#endif
