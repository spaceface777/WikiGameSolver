/*
MIT License

Copyright (c) 2020 Alex Ionescu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#ifdef _MSC_VER
#pragma warning(disable : 4214)
#endif

// #include <assert.h>
// #include <stdbool.h>
// #include <stddef.h>
// #include <stdint.h>

#define LZMA_MAX_SEQUENCE_SIZE 21

typedef enum _LZMA2_COMPRESSED_RESET_STATE {
  Lzma2NoReset = 0,
  Lzma2SimpleReset = 1,
  Lzma2PropertyReset = 2,
  Lzma2FullReset = 3
} LZMA2_COMPRESSED_RESET_STATE;

typedef union _LZMA2_CONTROL_BYTE {
  union {
    struct {
      uint8_t ResetState : 2;
      uint8_t Reserved : 5;
      uint8_t IsLzma : 1;
    } Raw;
    struct {
      uint8_t RawSize : 5;
      uint8_t ResetState : 2;
      uint8_t IsLzma : 1;
    } Lzma;
    struct {
      uint8_t : 7;
      uint8_t IsLzma : 1;
    } Common;
  } u;
  uint8_t Value;
} LZMA2_CONTROL_BYTE;
static_assert(sizeof(LZMA2_CONTROL_BYTE) == 1, "Invalid control byte size");

#define LZMA_LITERALS 256
#define LZMA_LC_TYPES 3
#define LZMA_LC_MODEL_SIZE (LZMA_LC_TYPES * LZMA_LITERALS)

#define LZMA_LC 3
#define LZMA_PB 2
#define LZMA_LP 0
#define LZMA_LITERAL_CODERS (1 << LZMA_LC)
#define LZMA_POSITION_COUNT (1 << LZMA_PB)

#define LZMA_MAX_LOW_LENGTH (1 << 3)
#define LZMA_MAX_MID_LENGTH (1 << 3)
#define LZMA_MAX_HIGH_LENGTH (1 << 8)
#define LZMA_MIN_LENGTH 2

#define LZMA_DISTANCE_SLOTS 64
#define LZMA_FIRST_CONTEXT_DISTANCE_SLOT 4
#define LZMA_FIRST_FIXED_DISTANCE_SLOT 14
#define LZMA_DISTANCE_ALIGN_BITS 4
#define LZMA_DISTANCE_ALIGN_SLOTS (1 << LZMA_DISTANCE_ALIGN_BITS)

#define LZMA_BIT_MODEL_SLOTS (1174 + (LZMA_LITERAL_CODERS * LZMA_LC_MODEL_SIZE))

typedef enum _LZMA_SEQUENCE_STATE {

  LzmaLitLitLitState,

  LzmaMatchLitLitState,
  LzmaRepLitLitState,
  LzmaLitShortrepLitLitState,

  LzmaMatchLitState,
  LzmaRepLitState,
  LzmaLitShortrepLitState,

  LzmaMaxLitState,

  LzmaLitMatchState = 7,
  LzmaLitRepState,
  LzmaLitShortrepState,

  LzmaNonlitMatchState,
  LzmaNonlitRepState,

  LzmaMaxState
} LZMA_SEQUENCE_STATE,
    *PLZMA_SEQUENCE_STATE;

bool BfRead(uint8_t* Byte);
bool BfSeek(uint32_t Length, const uint8_t** Bytes);
bool BfAlign(void);
void BfInitialize(const uint8_t* InputBuffer, uint32_t InputSize);
bool BfSetSoftLimit(uint32_t Remaining);
void BfResetSoftLimit(void);

bool DtRepeatSymbol(uint32_t Length, uint32_t Distance);
void DtInitialize(uint8_t* HistoryBuffer, uint32_t Position, uint32_t Offset);
bool DtSetLimit(uint32_t Limit);
void DtPutSymbol(uint8_t Symbol);
uint8_t DtGetSymbol(uint32_t Distance);
bool DtCanWrite(uint32_t* Position);
bool DtIsComplete(uint32_t* BytesProcessed);

uint8_t RcGetBitTree(uint16_t* BitModel, uint16_t Limit);
uint8_t RcGetReverseBitTree(uint16_t* BitModel, uint8_t HighestBit);
uint8_t RcDecodeMatchedBitTree(uint16_t* BitModel, uint8_t MatchByte);
uint32_t RcGetFixed(uint8_t HighestBit);
bool RcInitialize(uint16_t* ChunkSize);
uint8_t RcIsBitSet(uint16_t* Probability);
void RcNormalize(void);
bool RcCanRead(void);
bool RcIsComplete(uint32_t* Offset);
void RcSetDefaultProbability(uint16_t* Probability);

bool LzDecode(void);
bool LzInitialize(uint8_t Properties);
void LzResetState(void);

bool Lz2DecodeStream(uint32_t* BytesProcessed, bool GetSizeOnly);

#ifdef MINLZ_INTEGRITY_CHECKS

#define MINLZ_META_CHECKS 1

uint32_t XzCrc32(uint32_t Crc, const uint8_t* Buffer, uint32_t Length);
uint64_t XzCrc64(uint64_t Crc, const uint8_t* Buffer, uint32_t Length);
#define Crc32(Buffer, Length) XzCrc32(0, (const uint8_t*)Buffer, Length)
#define Crc64(Buffer, Length) XzCrc64(0, (const uint8_t*)Buffer, Length)
#endif

const uint8_t k_XzLzma2FilterIdentifier = 0x21;

const uint16_t k_XzStreamFooterMagic = 'ZY';

const uint8_t k_XzStreamHeaderMagic0 = 0xFD;
const uint32_t k_XzStreamHeaderMagic1 = 'ZXz7';
const uint8_t k_XzStreamHeaderMagic5 = 0x00;

const uint8_t k_XzBlockCheckSizes[] = {0,  4,  4,  4,  8,  8,  8,  16,
                                       16, 16, 32, 32, 32, 64, 64, 64};

typedef uint32_t vli_type;
#define VLI_BYTES_MAX (sizeof(vli_type) * 8 / 7)

typedef enum _XZ_CHECK_TYPES {
  XzCheckTypeNone = 0,
  XzCheckTypeCrc32 = 1,
  XzCheckTypeCrc64 = 4,
  XzCheckTypeSha2 = 10
} XZ_CHECK_TYPES;

typedef struct _XZ_STREAM_HEADER {
  uint8_t Magic[6];
  union {
    struct {
      uint8_t ReservedFlags;
      uint8_t CheckType : 4;
      uint8_t ReservedType : 4;
    } s;
    uint16_t Flags;
  } u;
  uint32_t Crc32;
} XZ_STREAM_HEADER, *PXZ_STREAM_HEADER;
static_assert(sizeof(XZ_STREAM_HEADER) == 12, "Invalid Stream Header Size");

typedef struct _XZ_STREAM_FOOTER {
  uint32_t Crc32;
  uint32_t BackwardSize;
  union {
    struct {
      uint8_t ReservedFlags;
      uint8_t CheckType : 4;
      uint8_t ReservedType : 4;
    } s;
    uint16_t Flags;
  } u;
  uint16_t Magic;
} XZ_STREAM_FOOTER, *PXZ_STREAM_FOOTER;
static_assert(sizeof(XZ_STREAM_FOOTER) == 12, "Invalid Stream Footer Size");

typedef struct _XZ_BLOCK_HEADER {
  uint8_t Size;
  union {
    struct {
      uint8_t FilterCount : 2;
      uint8_t Reserved : 4;
      uint8_t HasCompressedSize : 1;
      uint8_t HasUncompressedSize : 1;
    } s;
    uint8_t Flags;
  } u;
  struct {
    uint8_t Id;
    uint8_t Size;
    union {
      struct {
        uint8_t DictionarySize : 6;
        uint8_t Reserved : 2;
      } s;
      uint8_t Properties;
    } u;
  } LzmaFlags;
  uint8_t Padding[3];
  uint32_t Crc32;
} XZ_BLOCK_HEADER, *PXZ_BLOCK_HEADER;
static_assert(sizeof(XZ_BLOCK_HEADER) == 12, "Invalid Block Header Size");

typedef struct _DICTIONARY_STATE {
  uint8_t* Buffer;
  uint32_t BufferSize;
  uint32_t Start;
  uint32_t Offset;
  uint32_t Limit;
} DICTIONARY_STATE, *PDICTIONARY_STATE;
DICTIONARY_STATE Dictionary;

void DtInitialize(uint8_t* HistoryBuffer, uint32_t Size, uint32_t Offset) {
  Dictionary.Buffer = HistoryBuffer;
  Dictionary.Offset = Offset;
  Dictionary.BufferSize = Size;
}

bool DtSetLimit(uint32_t Limit) {
  if ((Dictionary.Offset + Limit) > Dictionary.BufferSize) {
    return false;
  }
  Dictionary.Limit = Dictionary.Offset + Limit;
  Dictionary.Start = Dictionary.Offset;
  return true;
}

bool DtIsComplete(uint32_t* BytesProcessed) {
  *BytesProcessed = Dictionary.Offset - Dictionary.Start;
  return (Dictionary.Offset == Dictionary.Limit);
}

bool DtCanWrite(uint32_t* Position) {
  *Position = Dictionary.Offset;
  return (Dictionary.Offset < Dictionary.Limit);
}

uint8_t DtGetSymbol(uint32_t Distance) {
  if (Distance > Dictionary.Offset) {
    return 0;
  }
  return Dictionary.Buffer[Dictionary.Offset - Distance];
}

void DtPutSymbol(uint8_t Symbol) {
  Dictionary.Buffer[Dictionary.Offset++] = Symbol;
}

bool DtRepeatSymbol(uint32_t Length, uint32_t Distance) {
  if (((Length + Dictionary.Offset) > Dictionary.Limit) ||
      (Distance > Dictionary.Offset)) {
    return false;
  }

  do {
    DtPutSymbol(DtGetSymbol(Distance));
  } while (--Length > 0);
  return true;
}

typedef struct _BUFFER_STATE {
  const uint8_t* Buffer;
  uint32_t Offset;
  uint32_t SoftLimit;
  uint32_t Size;
} BUFFER_STATE, *PBUFFER_STATE;
BUFFER_STATE In;

bool BfAlign(void) {
  uint8_t padByte;

  while (In.Offset & 3) {
    if (!BfRead(&padByte) || (padByte != 0)) {
      return false;
    }
  }
  return true;
}

bool BfSetSoftLimit(uint32_t Remaining) {
  if ((In.Size - In.Offset) < Remaining) {
    return false;
  }
  In.SoftLimit = In.Offset + Remaining;
  return true;
}

void BfResetSoftLimit(void) { In.SoftLimit = In.Size; }

bool BfSeek(uint32_t Length, const uint8_t** Bytes) {
  if ((In.Offset + Length) > In.SoftLimit) {
    *Bytes = 0;
    return false;
  }
  *Bytes = &In.Buffer[In.Offset];
  In.Offset += Length;
  return true;
}

bool BfRead(uint8_t* Byte) {
  const uint8_t* pByte;

  if (!BfSeek(sizeof(*Byte), &pByte)) {
    *Byte = 0;
    return false;
  }
  *Byte = *pByte;
  return true;
}

void BfInitialize(const uint8_t* InputBuffer, uint32_t InputSize) {
  In.Buffer = InputBuffer;
  In.Size = InputSize;
  In.SoftLimit = InputSize;
  In.Offset = 0;
}

bool Lz2DecodeChunk(uint32_t* BytesProcessed, uint32_t RawSize,
                    uint16_t CompressedSize) {
  uint32_t bytesProcessed;

  if (!LzDecode()) {
    return false;
  }

  if (!RcIsComplete(&bytesProcessed) || (bytesProcessed != CompressedSize)) {
    return false;
  }

  if (!DtIsComplete(&bytesProcessed) || (bytesProcessed != RawSize)) {
    return false;
  }
  *BytesProcessed += bytesProcessed;
  return true;
}

bool Lz2DecodeStream(uint32_t* BytesProcessed, bool GetSizeOnly) {
  const uint8_t* inBytes;
  LZMA2_CONTROL_BYTE controlByte;
  uint8_t propertyByte;
  uint32_t rawSize;
  uint16_t compressedSize;

  *BytesProcessed = 0;
  while (BfRead(&controlByte.Value)) {
    if (controlByte.Value == 0) {
      return true;
    }

    if (!BfSeek((controlByte.u.Common.IsLzma == 1) ? 4 : 2, &inBytes)) {
      break;
    }

    if (controlByte.u.Common.IsLzma == 1) {
      rawSize = controlByte.u.Lzma.RawSize << 16;
      compressedSize = (uint16_t)(inBytes[2] << 8);
      compressedSize += inBytes[3] + 1;
    } else {
      rawSize = 0;
      compressedSize = 0;
    }

    rawSize += inBytes[0] << 8;
    rawSize += inBytes[1] + 1;
    if (!GetSizeOnly && !DtSetLimit(rawSize)) {
      break;
    }
    if ((controlByte.u.Lzma.ResetState == Lzma2FullReset) ||
        (controlByte.u.Lzma.ResetState == Lzma2PropertyReset)) {
      if (!BfRead(&propertyByte) || !LzInitialize(propertyByte)) {
        break;
      }
    } else if (controlByte.u.Lzma.ResetState == Lzma2SimpleReset) {
      LzResetState();
    } else if (controlByte.u.Lzma.ResetState == Lzma2NoReset) {
      ;
    }

    if (GetSizeOnly) {
      *BytesProcessed += rawSize;
      BfSeek((controlByte.u.Common.IsLzma == 1) ? compressedSize : rawSize,
             &inBytes);
      continue;
    } else if (controlByte.u.Common.IsLzma == 0) {
      if (!BfSeek(rawSize, &inBytes)) {
        return false;
      }

      for (uint32_t i = 0; i < rawSize; i++) {
        DtPutSymbol(inBytes[i]);
      }

      *BytesProcessed += rawSize;
      continue;
    }

    if (!BfSetSoftLimit(compressedSize)) {
      break;
    }

    if (!RcInitialize(&compressedSize)) {
      break;
    }

    if (!Lz2DecodeChunk(BytesProcessed, rawSize, compressedSize)) {
      break;
    }

    BfResetSoftLimit();
  }
  return false;
}

typedef struct _LENGTH_DECODER_STATE {
  uint16_t Choice;
  uint16_t Choice2;

  uint16_t Low[LZMA_POSITION_COUNT][LZMA_MAX_LOW_LENGTH];
  uint16_t Mid[LZMA_POSITION_COUNT][LZMA_MAX_MID_LENGTH];
  uint16_t High[LZMA_MAX_HIGH_LENGTH];
} LENGTH_DECODER_STATE, *PLENGTH_DECODER_STATE;

typedef struct _DECODER_STATE {
  LZMA_SEQUENCE_STATE Sequence;

  uint32_t Rep0;
  uint32_t Rep1;
  uint32_t Rep2;
  uint32_t Rep3;

  uint32_t Len;

  union {
    struct {
      uint16_t Literal[LZMA_LITERAL_CODERS][LZMA_LC_MODEL_SIZE];

      uint16_t Rep[LzmaMaxState];
      uint16_t Rep0[LzmaMaxState];
      uint16_t Rep0Long[LzmaMaxState][LZMA_POSITION_COUNT];
      uint16_t Rep1[LzmaMaxState];
      uint16_t Rep2[LzmaMaxState];
      LENGTH_DECODER_STATE RepLen;

      uint16_t Match[LzmaMaxState][LZMA_POSITION_COUNT];
      uint16_t DistSlot[LZMA_FIRST_CONTEXT_DISTANCE_SLOT][LZMA_DISTANCE_SLOTS];
      uint16_t Dist[(1 << 7) - LZMA_FIRST_FIXED_DISTANCE_SLOT];
      uint16_t Align[LZMA_DISTANCE_ALIGN_SLOTS];
      LENGTH_DECODER_STATE MatchLen;
    } BitModel;
    uint16_t RawProbabilities[LZMA_BIT_MODEL_SLOTS];
  } u;
} DECODER_STATE, *PDECODER_STATE;
DECODER_STATE Decoder;
const uint8_t k_LzSupportedProperties =
    (LZMA_PB * 45) + (LZMA_LP * 9) + (LZMA_LC);

void LzSetLiteral(PLZMA_SEQUENCE_STATE State) {
  if (*State <= LzmaLitShortrepLitLitState) {
    *State = LzmaLitLitLitState;
  } else if (*State <= LzmaLitShortrepState) {
    *State = (LZMA_SEQUENCE_STATE)(*State - 3);
  } else {
    *State = (LZMA_SEQUENCE_STATE)(*State - 6);
  }
}

bool LzIsLiteral(LZMA_SEQUENCE_STATE State) { return State < LzmaMaxLitState; }

void LzSetMatch(PLZMA_SEQUENCE_STATE State) {
  *State = LzIsLiteral(*State) ? LzmaLitMatchState : LzmaNonlitMatchState;
}

void LzSetLongRep(PLZMA_SEQUENCE_STATE State) {
  *State = LzIsLiteral(*State) ? LzmaLitRepState : LzmaNonlitRepState;
}

void LzSetShortRep(PLZMA_SEQUENCE_STATE State) {
  *State = LzIsLiteral(*State) ? LzmaLitShortrepState : LzmaNonlitRepState;
}

uint16_t* LzGetLiteralSlot(void) {
  uint8_t symbol;
  symbol = DtGetSymbol(1);
  return Decoder.u.BitModel.Literal[symbol >> (8 - LZMA_LC)];
}

uint16_t* LzGetDistSlot(void) {
  uint8_t slotIndex;
  if (Decoder.Len < (LZMA_FIRST_CONTEXT_DISTANCE_SLOT + LZMA_MIN_LENGTH)) {
    slotIndex = (uint8_t)(Decoder.Len - LZMA_MIN_LENGTH);
  } else {
    slotIndex = LZMA_FIRST_CONTEXT_DISTANCE_SLOT - 1;
  }
  return Decoder.u.BitModel.DistSlot[slotIndex];
}

void LzDecodeLiteral(void) {
  uint16_t* probArray;
  uint8_t symbol, matchByte;
  probArray = LzGetLiteralSlot();
  if (LzIsLiteral(Decoder.Sequence)) {
    symbol = RcGetBitTree(probArray, (1 << 8));
  } else {
    matchByte = DtGetSymbol(Decoder.Rep0 + 1);
    symbol = RcDecodeMatchedBitTree(probArray, matchByte);
  }

  DtPutSymbol(symbol);
  LzSetLiteral(&Decoder.Sequence);
}

void LzDecodeLen(PLENGTH_DECODER_STATE LenState, uint8_t PosBit) {
  uint16_t* probArray;
  uint16_t limit;
  Decoder.Len = LZMA_MIN_LENGTH;
  if (RcIsBitSet(&LenState->Choice)) {
    if (RcIsBitSet(&LenState->Choice2)) {
      probArray = LenState->High;
      limit = LZMA_MAX_HIGH_LENGTH;
      Decoder.Len += LZMA_MAX_LOW_LENGTH + LZMA_MAX_MID_LENGTH;
    } else {
      probArray = LenState->Mid[PosBit];
      limit = LZMA_MAX_MID_LENGTH;
      Decoder.Len += LZMA_MAX_LOW_LENGTH;
    }
  } else {
    probArray = LenState->Low[PosBit];
    limit = LZMA_MAX_LOW_LENGTH;
  }
  Decoder.Len += RcGetBitTree(probArray, limit);
}

void LzDecodeMatch(uint8_t PosBit) {
  uint16_t* probArray;
  uint8_t distSlot, distBits;

  LzDecodeLen(&Decoder.u.BitModel.MatchLen, PosBit);
  Decoder.Rep3 = Decoder.Rep2;
  Decoder.Rep2 = Decoder.Rep1;
  Decoder.Rep1 = Decoder.Rep0;

  probArray = LzGetDistSlot();
  distSlot = RcGetBitTree(probArray, LZMA_DISTANCE_SLOTS);
  if (distSlot < LZMA_FIRST_CONTEXT_DISTANCE_SLOT) {
    Decoder.Rep0 = distSlot;
  } else {
    distBits = (distSlot >> 1) - 1;
    Decoder.Rep0 = (0b10 | (distSlot & 1)) << distBits;

    if (distSlot < LZMA_FIRST_FIXED_DISTANCE_SLOT) {
      probArray = &Decoder.u.BitModel.Dist[Decoder.Rep0 - distSlot];
    } else {
      Decoder.Rep0 |= RcGetFixed(distBits - LZMA_DISTANCE_ALIGN_BITS)
                      << LZMA_DISTANCE_ALIGN_BITS;
      distBits = LZMA_DISTANCE_ALIGN_BITS;
      probArray = Decoder.u.BitModel.Align;
    }
    Decoder.Rep0 |= RcGetReverseBitTree(probArray, distBits);
  }

  LzSetMatch(&Decoder.Sequence);
}

void LzDecodeRepLen(uint8_t PosBit, bool IsLongRep) {
  if (IsLongRep) {
    LzDecodeLen(&Decoder.u.BitModel.RepLen, PosBit);
    LzSetLongRep(&Decoder.Sequence);
  } else {
    Decoder.Len = 1;
    LzSetShortRep(&Decoder.Sequence);
  }
}

void LzDecodeRep0(uint8_t PosBit) {
  uint8_t bit;

  bit = RcIsBitSet(&Decoder.u.BitModel.Rep0Long[Decoder.Sequence][PosBit]);
  LzDecodeRepLen(PosBit, bit);
}

void LzDecodeLongRep(uint8_t PosBit) {
  uint32_t newRep;
  if (RcIsBitSet(&Decoder.u.BitModel.Rep1[Decoder.Sequence])) {
    if (RcIsBitSet(&Decoder.u.BitModel.Rep2[Decoder.Sequence])) {
      newRep = Decoder.Rep3;
      Decoder.Rep3 = Decoder.Rep2;
    } else {
      newRep = Decoder.Rep2;
    }
    Decoder.Rep2 = Decoder.Rep1;
  } else {
    newRep = Decoder.Rep1;
  }
  Decoder.Rep1 = Decoder.Rep0;
  Decoder.Rep0 = newRep;
  LzDecodeRepLen(PosBit, true);
}

void LzDecodeRep(uint8_t PosBit) {
  if (RcIsBitSet(&Decoder.u.BitModel.Rep0[Decoder.Sequence])) {
    LzDecodeLongRep(PosBit);
  } else {
    LzDecodeRep0(PosBit);
  }
}

bool LzDecode(void) {
  uint32_t position;
  uint8_t posBit;

  while (DtCanWrite(&position) && RcCanRead()) {
    posBit = position & (LZMA_POSITION_COUNT - 1);
    if (RcIsBitSet(&Decoder.u.BitModel.Match[Decoder.Sequence][posBit])) {
      if (RcIsBitSet(&Decoder.u.BitModel.Rep[Decoder.Sequence])) {
        LzDecodeRep(posBit);
      } else {
        LzDecodeMatch(posBit);
      }

      if (!DtRepeatSymbol(Decoder.Len, Decoder.Rep0 + 1)) {
        return false;
      }
      Decoder.Len = 0;
    } else {
      LzDecodeLiteral();
    }
  }
  RcNormalize();
  return (Decoder.Len == 0);
}

void LzResetState(void) {
  Decoder.Sequence = LzmaLitLitLitState;
  Decoder.Rep0 = Decoder.Rep1 = Decoder.Rep2 = Decoder.Rep3 = 0;
  static_assert((LZMA_BIT_MODEL_SLOTS * 2) == sizeof(Decoder.u.BitModel),
                "Invalid size");
  for (int i = 0; i < LZMA_BIT_MODEL_SLOTS; i++) {
    RcSetDefaultProbability(&Decoder.u.RawProbabilities[i]);
  }
}

bool LzInitialize(uint8_t Properties) {
  if (Properties != k_LzSupportedProperties) {
    return false;
  }
  LzResetState();
  return true;
}

#define LZMA_RC_PROBABILITY_BITS 11
#define LZMA_RC_MAX_PROBABILITY (1 << LZMA_RC_PROBABILITY_BITS)
const uint16_t k_LzmaRcHalfProbability = LZMA_RC_MAX_PROBABILITY / 2;

#define LZMA_RC_ADAPTATION_RATE_SHIFT 5

#define LZMA_RC_MIN_RANGE (1 << 24)

#define LZMA_RC_INIT_BYTES 5

typedef struct _RANGE_DECODER_STATE {
  const uint8_t* Start;
  const uint8_t* Limit;

  uint32_t Range;
  uint32_t Code;
} RANGE_DECODER_STATE, *PRANGE_DECODER_STATE;
RANGE_DECODER_STATE RcState;

bool RcInitialize(uint16_t* ChunkSize) {
  uint8_t i, rcByte;
  const uint8_t* chunkEnd;

  if (!BfSeek(*ChunkSize, &chunkEnd)) {
    return false;
  }
  BfSeek(-*ChunkSize, &chunkEnd);

  RcState.Range = (uint32_t)-1;
  RcState.Code = 0;
  for (i = 0; i < LZMA_RC_INIT_BYTES; i++) {
    BfRead(&rcByte);
    RcState.Code = (RcState.Code << 8) | rcByte;
  }
  BfSeek(0, &RcState.Start);
  RcState.Limit = RcState.Start + *ChunkSize;
  *ChunkSize -= LZMA_RC_INIT_BYTES;
  return true;
}

bool RcCanRead(void) {
  const uint8_t* pos;

  BfSeek(0, &pos);
  return pos <= RcState.Limit;
}

bool RcIsComplete(uint32_t* BytesProcessed) {
  const uint8_t* pos;

  BfSeek(0, &pos);
  *BytesProcessed = (uint32_t)(pos - RcState.Start);
  return (RcState.Code == 0);
}

void RcNormalize(void) {
  uint8_t rcByte;

  if (RcState.Range < LZMA_RC_MIN_RANGE) {
    RcState.Range <<= 8;
    RcState.Code <<= 8;
    BfRead(&rcByte);
    RcState.Code |= rcByte;
  }
}

void RcAdapt(bool Miss, uint16_t* Probability) {
  if (Miss) {
    *Probability -= *Probability >> LZMA_RC_ADAPTATION_RATE_SHIFT;
  } else {
    *Probability += (LZMA_RC_MAX_PROBABILITY - *Probability) >>
                    LZMA_RC_ADAPTATION_RATE_SHIFT;
  }
}

uint8_t RcIsBitSet(uint16_t* Probability) {
  uint32_t bound;
  uint8_t bit;

  RcNormalize();
  bound = (RcState.Range >> LZMA_RC_PROBABILITY_BITS) * *Probability;
  if (RcState.Code < bound) {
    RcState.Range = bound;
    bit = 0;
  } else {
    RcState.Range -= bound;
    RcState.Code -= bound;
    bit = 1;
  }

  RcAdapt(bit, Probability);
  return bit;
}

uint8_t RcIsFixedBitSet(void) {
  uint8_t bit;
  RcNormalize();
  RcState.Range >>= 1;
  if (RcState.Code < RcState.Range) {
    bit = 0;
  } else {
    RcState.Code -= RcState.Range;
    bit = 1;
  }
  return bit;
}

uint8_t RcGetBitTree(uint16_t* BitModel, uint16_t Limit) {
  uint16_t symbol;
  for (symbol = 1; symbol < Limit;) {
    symbol = (uint16_t)(symbol << 1) | RcIsBitSet(&BitModel[symbol]);
  }
  return (symbol - Limit) & 0xFF;
}

uint8_t RcGetReverseBitTree(uint16_t* BitModel, uint8_t HighestBit) {
  uint16_t symbol;
  uint8_t i, bit, result;

  for (i = 0, symbol = 1, result = 0; i < HighestBit; i++) {
    bit = RcIsBitSet(&BitModel[symbol]);
    symbol = (uint16_t)(symbol << 1) | bit;
    result |= bit << i;
  }
  return result;
}

uint8_t RcDecodeMatchedBitTree(uint16_t* BitModel, uint8_t MatchByte) {
  uint16_t symbol, bytePos, matchBit;
  uint8_t bit;
  for (bytePos = MatchByte, symbol = 1; symbol < 0x100; bytePos <<= 1) {
    matchBit = (bytePos >> 7) & 1;

    bit = RcIsBitSet(&BitModel[symbol + (0x100 * (matchBit + 1))]);
    symbol = (uint16_t)(symbol << 1) | bit;

    if (matchBit != bit) {
      while (symbol < 0x100) {
        symbol = (uint16_t)(symbol << 1) | RcIsBitSet(&BitModel[symbol]);
      }
      break;
    }
  }
  return symbol & 0xFF;
}

uint32_t RcGetFixed(uint8_t HighestBit) {
  uint32_t symbol;

  symbol = 0;
  do {
    symbol = (symbol << 1) | RcIsFixedBitSet();
  } while (--HighestBit > 0);
  return symbol;
}

void RcSetDefaultProbability(uint16_t* Probability) {
  *Probability = k_LzmaRcHalfProbability;
}

#ifdef MINLZ_INTEGRITY_CHECKS
const uint32_t k_Crc32Polynomial = UINT32_C(0xEDB88320);
const uint64_t k_Crc64Polynomial = UINT64_C(0xC96C5795D7870F42);

typedef struct _CHECKSUM_STATE {
  uint32_t Crc32Table[256];
  uint64_t Crc64Table[256];
  bool Initialized;
} CHECKSUM_STATE, *PCHECKSUM_STATE;
CHECKSUM_STATE Checksum;

void XzCrcInitialize(void) {
  uint32_t i;
  uint32_t j;
  uint32_t crc32;
  uint64_t crc64;

  if (!Checksum.Initialized) {
    for (i = 0; i < 256; i++) {
      crc32 = i;
      crc64 = i;

      for (j = 0; j < 8; j++) {
        if (crc32 & 1) {
          crc32 = (crc32 >> 1) ^ k_Crc32Polynomial;
        } else {
          crc32 >>= 1;
        }

        if (crc64 & 1) {
          crc64 = (crc64 >> 1) ^ k_Crc64Polynomial;
        } else {
          crc64 >>= 1;
        }
      }

      Checksum.Crc32Table[i] = crc32;
      Checksum.Crc64Table[i] = crc64;
    }

    Checksum.Initialized = true;
  }
}

uint32_t XzCrc32(uint32_t Crc, const uint8_t* Buffer, uint32_t Length) {
  uint32_t i;
  for (XzCrcInitialize(), Crc = ~Crc, i = 0; i < Length; ++i) {
    Crc = Checksum.Crc32Table[Buffer[i] ^ (Crc & 0xFF)] ^ (Crc >> 8);
  }
  return ~Crc;
}

uint64_t XzCrc64(uint64_t Crc, const uint8_t* Buffer, uint32_t Length) {
  uint32_t i;

  for (XzCrcInitialize(), Crc = ~Crc, i = 0; i < Length; ++i) {
    Crc = Checksum.Crc64Table[Buffer[i] ^ (Crc & 0xFF)] ^ (Crc >> 8);
  }
  return ~Crc;
}
#endif

#ifdef _WIN32
void __security_check_cookie(_In_ uintptr_t _StackCookie) {
  (void)(_StackCookie);
}
#endif

#ifdef MINLZ_META_CHECKS

typedef struct _CONTAINER_STATE {
  uint32_t HeaderSize;
  uint32_t IndexSize;

  uint32_t UncompressedBlockSize;
  uint32_t UnpaddedBlockSize;

  uint32_t ChecksumSize;
  uint8_t ChecksumType;
  bool ChecksumError;
} CONTAINER_STATE, *PCONTAINER_STATE;
CONTAINER_STATE Container;
#endif

#ifdef MINLZ_META_CHECKS
bool XzDecodeVli(vli_type* Vli) {
  uint8_t vliByte;
  uint32_t bitPos;

  if (!BfRead(&vliByte)) {
    return false;
  }
  *Vli = vliByte & 0x7F;

  bitPos = 7;
  while ((vliByte & 0x80) != 0) {
    if (!BfRead(&vliByte)) {
      return false;
    }

    if ((bitPos == (7 * VLI_BYTES_MAX)) || (vliByte == 0)) {
      return false;
    }

    *Vli |= (vli_type)((vliByte & 0x7F) << bitPos);
    bitPos += 7;
  }
  return true;
}

bool XzDecodeIndex(void) {
  uint32_t vli;
  const uint8_t* indexStart;
  const uint8_t* indexEnd;
  const uint32_t* pCrc32;
  uint8_t indexByte;

  BfSeek(0, &indexStart);

  if (!BfRead(&indexByte) || (indexByte != 0)) {
    return false;
  }

  if (!XzDecodeVli(&vli) || (vli != 1)) {
    return false;
  }

  if (!XzDecodeVli(&vli) || (Container.UnpaddedBlockSize != vli)) {
    return false;
  }

  if (!XzDecodeVli(&vli) || (Container.UncompressedBlockSize != vli)) {
    return false;
  }

  if (!BfAlign()) {
    return false;
  }

  BfSeek(0, &indexEnd);
  Container.IndexSize = (uint32_t)(indexEnd - indexStart);

  if (!BfSeek(sizeof(*pCrc32), (const uint8_t**)&pCrc32)) {
    return false;
  }
#ifdef MINLZ_INTEGRITY_CHECKS

  if (Crc32(indexStart, Container.IndexSize) != *pCrc32) {
    Container.ChecksumError = true;
  }
#endif
  return true;
}

bool XzDecodeStreamFooter(void) {
  PXZ_STREAM_FOOTER streamFooter;

  if (!BfSeek(sizeof(*streamFooter), (const uint8_t**)&streamFooter)) {
    return false;
  }

  if (streamFooter->Magic != k_XzStreamFooterMagic) {
    return false;
  }

  if ((streamFooter->u.s.ReservedFlags != 0) ||
      (streamFooter->u.s.ReservedType != 0) ||
      (streamFooter->u.s.CheckType != Container.ChecksumType)) {
    return false;
  }

  if (Container.IndexSize != (streamFooter->BackwardSize * 4)) {
    return false;
  }
#ifdef MINLZ_INTEGRITY_CHECKS

  if (Crc32(&streamFooter->BackwardSize, sizeof(streamFooter->BackwardSize) +
                                             sizeof(streamFooter->u.Flags)) !=
      streamFooter->Crc32) {
    Container.ChecksumError = true;
  }
#endif
  return true;
}
#endif

#if MINLZ_INTEGRITY_CHECKS
bool XzCrc(uint8_t* OutputBuffer, uint32_t BlockSize, const uint8_t* InputEnd) {
  switch (Container.ChecksumType) {
    case XzCheckTypeCrc32:
      return Crc32(OutputBuffer, BlockSize) != *(uint32_t*)InputEnd;
    case XzCheckTypeCrc64:
      return Crc64(OutputBuffer, BlockSize) != *(uint64_t*)InputEnd;
    default:
      return false;
  }
}
#endif

bool XzDecodeBlock(uint8_t* OutputBuffer, uint32_t* BlockSize) {
#ifdef MINLZ_META_CHECKS
  const uint8_t *inputStart, *inputEnd;
#endif

#ifdef MINLZ_META_CHECKS
  BfSeek(0, &inputStart);
#endif
  if (!Lz2DecodeStream(BlockSize, OutputBuffer == NULL)) {
    return false;
  }
#ifdef MINLZ_META_CHECKS
  BfSeek(0, &inputEnd);
  Container.UnpaddedBlockSize =
      Container.HeaderSize + (uint32_t)(inputEnd - inputStart);
  Container.UncompressedBlockSize = *BlockSize;
#endif

  if (!BfAlign()) {
    return false;
  }
#ifdef MINLZ_META_CHECKS

  if (!BfSeek(Container.ChecksumSize, &inputEnd)) {
    return false;
  }
#endif
  (void)(OutputBuffer);
#ifdef MINLZ_INTEGRITY_CHECKS
  if ((OutputBuffer != NULL) && !(XzCrc(OutputBuffer, *BlockSize, inputEnd))) {
    Container.ChecksumError = true;
  }
#endif
#ifdef MINLZ_META_CHECKS
  Container.UnpaddedBlockSize += Container.ChecksumSize;
#endif
  return true;
}

bool XzDecodeStreamHeader(void) {
  PXZ_STREAM_HEADER streamHeader;

  if (!BfSeek(sizeof(*streamHeader), (const uint8_t**)&streamHeader)) {
    return false;
  }
#ifdef MINLZ_META_CHECKS

  if ((*(uint32_t*)&streamHeader->Magic[1] != k_XzStreamHeaderMagic1) ||
      (streamHeader->Magic[0] != k_XzStreamHeaderMagic0) ||
      (streamHeader->Magic[5] != k_XzStreamHeaderMagic5)) {
    return false;
  }

  if ((streamHeader->u.s.ReservedFlags != 0) ||
      (streamHeader->u.s.ReservedType != 0)) {
    return false;
  }

  Container.ChecksumType = streamHeader->u.s.CheckType;
  Container.ChecksumSize = k_XzBlockCheckSizes[streamHeader->u.s.CheckType];
  if ((Container.ChecksumType != XzCheckTypeNone) &&
      (Container.ChecksumType != XzCheckTypeCrc32) &&
      (Container.ChecksumType != XzCheckTypeCrc64)) {
    Container.ChecksumError = true;
  }
#endif
#ifdef MINLZ_INTEGRITY_CHECKS

  if (Crc32(&streamHeader->u.Flags, sizeof(streamHeader->u.Flags)) !=
      streamHeader->Crc32) {
    Container.ChecksumError = true;
  }
#endif
  return true;
}

bool XzDecodeBlockHeader(void) {
  PXZ_BLOCK_HEADER blockHeader;
#ifdef MINLZ_META_CHECKS
  uint32_t dictionarySize;
#endif

  if (!BfSeek(sizeof(*blockHeader), (const uint8_t**)&blockHeader) ||
      (blockHeader->Size == 0)) {
    BfSeek((uint32_t)(-(uint16_t)sizeof(*blockHeader)),
           (const uint8_t**)&blockHeader);
    return false;
  }
#ifdef MINLZ_META_CHECKS

  Container.HeaderSize = (blockHeader->Size + 1) * 4;
  if (Container.HeaderSize != sizeof(*blockHeader)) {
    return false;
  }

  if (blockHeader->u.Flags != 0) {
    return false;
  }

  if (blockHeader->LzmaFlags.Id != k_XzLzma2FilterIdentifier) {
    return false;
  }

  if (blockHeader->LzmaFlags.Size !=
      sizeof(blockHeader->LzmaFlags.u.Properties)) {
    return false;
  }
  dictionarySize = blockHeader->LzmaFlags.u.s.DictionarySize;
  if (dictionarySize > 39) {
    return false;
  }
#ifdef MINLZ_INTEGRITY_CHECKS

  if (Crc32(blockHeader, Container.HeaderSize - sizeof(blockHeader->Crc32)) !=
      blockHeader->Crc32) {
    Container.ChecksumError = true;
  }
#endif
#endif
  return true;
}

bool XzDecode(const uint8_t* InputBuffer, uint32_t InputSize,
              uint8_t* OutputBuffer, uint32_t* OutputSize) {
  BfInitialize(InputBuffer, InputSize);
  DtInitialize(OutputBuffer, *OutputSize, 0);

  if (!XzDecodeStreamHeader()) {
    return false;
  }

  if (XzDecodeBlockHeader()) {
    if (!XzDecodeBlock(OutputBuffer, OutputSize)) {
      return false;
    }
  } else {
    *OutputSize = 0;
  }
#ifdef MINLZ_META_CHECKS

  if (!XzDecodeIndex()) {
    return false;
  }

  if (!XzDecodeStreamFooter()) {
    return false;
  }
#endif
  return true;
}

bool XzChecksumError(void) {
#ifdef MINLZ_INTEGRITY_CHECKS
  return Container.ChecksumError;
#else
  return false;
#endif
}
