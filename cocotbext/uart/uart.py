"""

Copyright (c) 2020 Alex Forencich

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

"""

import logging

import cocotb
from cocotb.queue import Queue
from cocotb.triggers import FallingEdge, Timer, First, Event

from .version import __version__


class UartSource:
    def __init__(self, data, baud=9600, bits=8, stop_bits=1, *args, **kwargs):
        self.log = logging.getLogger(f"cocotb.{data._path}")
        self._data = data
        self._baud = baud
        self._bits = bits
        self._stop_bits = stop_bits

        self.log.info("UART source")
        self.log.info("cocotbext-uart version %s", __version__)
        self.log.info("Copyright (c) 2020 Alex Forencich")
        self.log.info("https://github.com/alexforencich/cocotbext-uart")

        super().__init__(*args, **kwargs)

        self.active = False
        self.queue = Queue()

        self._wridle = Event()
        self._wridle.set()

        self._data.setimmediatevalue(1)

        self.log.info("UART source configuration:")
        self.log.info("  Baud rate: %d bps", self._baud)
        self.log.info("  Byte size: %d bits", self._bits)
        self.log.info("  Stop bits: %f bits", self._stop_bits)

        self._run_cr = None
        self._restart()

    def _restart(self):
        if self._run_cr is not None:
            self._run_cr.kill()
        self._run_cr = cocotb.start_soon(self._run(self._data, self._baud, self._bits, self._stop_bits))

    @property
    def baud(self):
        return self._baud

    @baud.setter
    def baud(self, value):
        self.baud = value
        self._restart()

    @property
    def bits(self):
        return self._bits

    @bits.setter
    def bits(self, value):
        self.bits = value
        self._restart()

    @property
    def stop_bits(self):
        return self._stop_bits

    @stop_bits.setter
    def stop_bits(self, value):
        self.stop_bits = value
        self._restart()

    async def write(self, data):
        for b in data:
            await self.queue.put(int(b))
            self._wridle.clear()

    def write_nowait(self, data):
        for b in data:
            self.queue.put_nowait(int(b))
        self._wridle.clear()

    def count(self):
        return self.queue.qsize()

    def empty(self):
        return self.queue.empty()

    def idle(self):
        return self.empty() and not self.active

    def clear(self):
        while not self.queue.empty():
            frame = self.queue.get_nowait()

    async def wait(self):
        await self._wridle.wait()

    async def _run(self, data, baud, bits, stop_bits):
        self.active = False

        bit_t = Timer(int(1e9/self.baud), 'ns')
        stop_bit_t = Timer(int(1e9/self.baud*stop_bits), 'ns')

        while True:
            if self.empty():
                self.active = False
                self._wridle.set()

            b = await self.queue.get()
            self.active = True

            self.log.info("Write byte 0x%02x", b)

            # start bit
            data.value = 0
            await bit_t

            # data bits
            for k in range(self.bits):
                data.value = b & 1
                b >>= 1
                await bit_t

            # stop bit
            data.value = 1
            await stop_bit_t


class UartSink:

    def __init__(self, data, baud=9600, bits=8, stop_bits=1, *args, **kwargs):
        self.log = logging.getLogger(f"cocotb.{data._path}")
        self._data = data
        self._baud = baud
        self._bits = bits
        self._stop_bits = stop_bits

        self.log.info("UART sink")
        self.log.info("cocotbext-uart version %s", __version__)
        self.log.info("Copyright (c) 2020 Alex Forencich")
        self.log.info("https://github.com/alexforencich/cocotbext-uart")

        super().__init__(*args, **kwargs)

        self.active = False
        self.queue = Queue()
        self.sync = Event()

        self.log.info("UART sink configuration:")
        self.log.info("  Baud rate: %d bps", self._baud)
        self.log.info("  Byte size: %d bits", self._bits)
        self.log.info("  Stop bits: %f bits", self._stop_bits)

        self._run_cr = None
        self._restart()

    def _restart(self):
        if self._run_cr is not None:
            self._run_cr.kill()
        self._run_cr = cocotb.start_soon(self._run(self._data, self._baud, self._bits, self._stop_bits))

    @property
    def baud(self):
        return self._baud

    @baud.setter
    def baud(self, value):
        self.baud = value
        self._restart()

    @property
    def bits(self):
        return self._bits

    @bits.setter
    def bits(self, value):
        self.bits = value
        self._restart()

    @property
    def stop_bits(self):
        return self._stop_bits

    @stop_bits.setter
    def stop_bits(self, value):
        self.stop_bits = value
        self._restart()

    async def read(self, count=-1):
        while self.empty():
            self.sync.clear()
            await self.sync.wait()
        return self.read_nowait(count)

    def read_nowait(self, count=-1):
        if count < 0:
            count = self.queue.qsize()
        if self.bits == 8:
            data = bytearray()
        else:
            data = []
        for k in range(count):
            data.append(self.queue.get_nowait())
        return data

    def count(self):
        return self.queue.qsize()

    def empty(self):
        return self.queue.empty()

    def idle(self):
        return not self.active

    def clear(self):
        while not self.queue.empty():
            frame = self.queue.get_nowait()

    async def wait(self, timeout=0, timeout_unit='ns'):
        if not self.empty():
            return
        self.sync.clear()
        if timeout:
            await First(self.sync.wait(), Timer(timeout, timeout_unit))
        else:
            await self.sync.wait()

    async def _run(self, data, baud, bits, stop_bits):
        self.active = False

        half_bit_t = Timer(int(1e9/self.baud/2), 'ns')
        bit_t = Timer(int(1e9/self.baud), 'ns')
        stop_bit_t = Timer(int(1e9/self.baud*stop_bits), 'ns')

        while True:
            await FallingEdge(data)

            self.active = True

            # start bit
            await half_bit_t

            # data bits
            b = 0
            for k in range(bits):
                await bit_t
                b |= bool(data.value.integer) << k

            # stop bit
            await stop_bit_t

            self.log.info("Read byte 0x%02x", b)

            self.queue.put_nowait(b)
            self.sync.set()

            self.active = False

import random
import warnings
from cocotb.triggers import RisingEdge            
class FifoDriver:
    
    def __init__(self, clk, reset, din, wr_en, dout, rd_en, full, overflow, empty, underflow, *args, **kwargs):
        self.log = logging.getLogger(f"cocotb.fifo")
        self._clk = clk        
        self._reset = reset
        self._din = din        
        self._wr_en = wr_en
        self._dout = dout        
        self._rd_en = rd_en
        self._full = full
        self._overflow = overflow
        self._empty = empty
        self._underflow = underflow
        

        self.log.info("Setup Driver")
        
        self.wractive = False
        self.wrqueue = Queue()
        self.rdactive = False
        self.rdqueue = Queue()

        self._wridle = Event()
        self._wridle.set()
        self._rdidle = Event()
        self._rdidle.set()

        self._wrrun_cr = None
        self._rdrun_cr = None
        self._restart()

    def _restart(self):
        self.expected_overflow = 0
        self.expected_empty = 1
        self.expected_underflow = 0
        self.expected_full = 0
        if self._wrrun_cr is not None:
            self._wrrun_cr.kill()
        self._wrrun_cr = cocotb.start_soon(self._wrrun())
        if self._rdrun_cr is not None:
            self._rdrun_cr.kill()
        self._rdrun_cr = cocotb.start_soon(self._rdrun())

    @property
    def underflow(self):
        if 'x' == str(self._underflow.value):
            return 0
        else:
            return self._underflow
    
    @property
    def overflow(self):
        if 'x' == str(self._overflow.value):
            return 0
        else:
            return self._overflow
    
    @property
    def dout(self):
        return int(str(self._dout.value), 2)
    #def count(self):
    #    return self.wrqueue.qsize()

    def wrempty(self):
        return self.wrqueue.empty()

    def rdempty(self):
        return self.rdqueue.empty()

    #def idle(self):
    #    return not self.wractive
    
    async def _wrrun(self):
        self.wractive = False
        
        while True:
            await RisingEdge(self._clk)
            if 1 == self.overflow:
                if self.expected_overflow == self.overflow:
                    self.log.info(f"FIFO Overflow Detected as Expected")
                else:
                    self.log.warning(f"FIFO Overflow not Expected")

            
            if self.wrempty():
                self.wractive = False
                self._wridle.set()
                self._din.value = 0x0
                self._wr_en.value = 0
            else:
                b = await self.wrqueue.get()
                self.wractive = True
                self._din.value = b
                self._wr_en.value = 1
                self.log.info(f"Write FIFO 0x{b:04x}")

    
    async def _rdrun(self):
        self.rdactive = False
        
        self.check_read = None
        self.check_read_dly = None
        
        while True:
            await RisingEdge(self._clk)
            if 1 == self.underflow:
                if self.expected_underflow == self.underflow:
                    self.log.info(f"FIFO Underflow Detected as Expected")
                else:
                    self.log.warning(f"FIFO Underflow not Expected")
            
            
            if not self.check_read_dly is None and not self.dout == self.check_read_dly:
                msg = f"Incorrect value returned, 0x{self.dout:04x} 0x{self.check_read_dly:04x}"
                self.log.error(msg)
                warnings.simplefilter("ignore", category=FutureWarning)
                raise Exception(msg)
            
            self.check_read_dly = self.check_read
            self.check_read = None
            if self.rdempty():
                self.rdactive = False
                self._rdidle.set()
                self._rd_en.value = 0
            else:
                b = await self.rdqueue.get()
                self.rdactive = True
                self._rd_en.value = 1
                if b is None:
                    self.log.info(f"Read FIFO")
                else:
                    self.log.info(f"Read FIFO 0x{b:04x}")
                    self.check_read = b
    
    async def write(self, data=None, overflow=0):
        self.expected_overflow = overflow
        if data is None:
            data = random.randint(0x0, 0xffff)
        await self.wrqueue.put(data)
        await RisingEdge(self._clk)
        self._wridle.clear()
        return data
    
    def write_nowait(self, data=None, overflow=0):
        self.expected_overflow = overflow
        if data is None:
            data = random.randint(0x0, 0xffff)
        self.wrqueue.put_nowait(data)
        self._wridle.clear()
        return data
            
    async def read(self, data=None, underflow=0):
        self.expected_underflow = underflow
        await self.rdqueue.put(data)
        await RisingEdge(self._clk)
        self._rdidle.clear()

    def read_nowait(self, data=None, underflow=0):
        self.expected_underflow = underflow
        self.rdqueue.put_nowait(data)
        self._rdidle.clear()


class Mem2PDriver:
    
    def __init__(self, clka, ena, wea, addra, dina, clkb, enb, addrb, doutb, *args, **kwargs):
        self.log = logging.getLogger(f"cocotb.mem2p")
        self.log.level = logging.DEBUG
        self._clka = clka        
        self._ena = ena       
        self._wea = wea       
        self._addra = addra       
        self._dina = dina        
        self._clkb = clkb       
        self._enb = enb       
        self._addrb = addrb       
        self._doutb = doutb   
        self.din_mask = 2**len(self._dina)-1
        self.mask = 2**len(self._wea)-1
        

        self.log.debug("Setup Mem2P Configuration")
        self.log.debug(f"  Write Memory Width: {len(self._dina)}")
        self.log.debug(f"  Write Memory Depth: {2**len(self._addra)}")
        self.log.debug(f"  Read Memory Width:  {len(self._doutb)}")
        self.log.debug(f"  Read Memory Depth:  {2**len(self._addrb)}")
        
        self.mem_array = []
        for i in range(2**len(self._addra)):
            self.mem_array.append(0)
        
        self.wractive = False
        self.wrqueue = Queue()
        self.rdactive = False
        self.rdqueue = Queue()

        self._wridle = Event()
        self._wridle.set()
        self._rdidle = Event()
        self._rdidle.set()

        self._wrrun_cr = None
        self._rdrun_cr = None
        self._restart()

    def _restart(self):
        if self._wrrun_cr is not None:
            self._wrrun_cr.kill()
        self._wrrun_cr = cocotb.start_soon(self._wrrun())
        if self._rdrun_cr is not None:
            self._rdrun_cr.kill()
        self._rdrun_cr = cocotb.start_soon(self._rdrun())

    @property
    def doutb(self):
        return int(str(self._doutb.value), 2)
        
    def wrempty(self):
        return self.wrqueue.empty()

    def rdempty(self):
        return self.rdqueue.empty()
    
    def mask_entend(self, wea):
        mask = 0
        i = 0
        while not 0 == wea:
            if 1 == (wea & 0x1):
                mask |= 0xff << (i*8)
            wea = wea >> 1
            i += 1
        
        return mask

    async def _wrrun(self):
        self.wractive = False
        
        while True:
            await RisingEdge(self._clka)

            
            if self.wrempty():
                self.wractive = False
                self._wridle.set()
                self._addra.value = 0x0
                self._dina.value = 0x0
                self._ena.value = 0
                self._wea.value = 0
            else:
                self.wractive = True
                addr, data, wea = await self.wrqueue.get()
                self._addra.value = addr
                self._dina.value = data
                self._ena.value = 1
                self._wea.value = wea & self.mask
                mem_mask = self.mask_entend(wea & self.mask)
                self.mem_array[addr] = ((self.mem_array[addr] & ~mem_mask) | (data & mem_mask)) & self.din_mask
                self.log.info(f"Write Mem2p 0x{addr:04x}: 0x{data:04x}")

    
    async def _rdrun(self):
        self.rdactive = False
        
        self.check_read = None
        self.check_read_dly = None
        self.addr_dly1 = None
        self.addr_dly0 = None
        
        while True:
            await RisingEdge(self._clkb)
           
            if not self.check_read_dly is None and not self.doutb == self.check_read_dly:
                msg = f"Incorrect value returned, 0x{self.doutb:04x} 0x{self.check_read_dly:04x}"
                self.log.error(msg)
                warnings.simplefilter("ignore", category=FutureWarning)
                raise Exception(msg)
             
            if not self.addr_dly1  is None and not self.doutb == self.mem_array[self.addr_dly1] :
                msg = f"Incorrect value returned, 0x{self.addr_dly1:04x}"
                self.log.error(msg)
                warnings.simplefilter("ignore", category=FutureWarning)
                raise Exception(msg)
           
            self.check_read_dly = self.check_read
            self.check_read = None
            self.addr_dly1 = self.addr_dly0
            self.addr_dly0 = None
            if self.rdempty():
                self.rdactive = False
                self._rdidle.set()
                self._addrb.value = 0
                self._enb.value = 0
            else:
                self.rdactive = True
                addr, data = await self.rdqueue.get()
                self._addrb.value = addr
                self._enb.value = 1

                if data is None:
                    self.log.info(f"Read Mem2p 0x{addr:04x}: 0x{self.mem_array[addr]:04x}")
                    self.addr_dly0 = addr
                else:
                    self.log.info(f"Read Mem2p 0x{addr:04x}: 0x{data:04x}")
                    self.check_read = data
    
    async def write(self, addr=None, data=None, wea=None):
        if addr is None:
            addr = random.randint(0x0, 2**len(self._addra)-1)
        if data is None:
            data = random.randint(0x0, self.din_mask)
        if wea is None:
            wea = random.randint(0x0, 0xffffffff)
        await self.wrqueue.put([addr, data, wea])
        await RisingEdge(self._clka)
        self._wridle.clear()
        return data
    
    def write_nowait(self, addr=None, data=None, wea=None):
        if data is None:
            data = random.randint(0x0, self.din_mask)
        self.wrqueue.put_nowait([addr, data, wea])
        self._wridle.clear()
        return data
            
    async def read(self, addr=None, data=None):
        if addr is None:
            addr = random.randint(0x0, 2**len(self._addra)-1)
        await self.rdqueue.put([addr, data])
        await RisingEdge(self._clkb)
        self._rdidle.clear()

    def read_nowait(self, addr=0x0000, data=None):
        self.rdqueue.put_nowait([addr, data])
        self._rdidle.clear()

