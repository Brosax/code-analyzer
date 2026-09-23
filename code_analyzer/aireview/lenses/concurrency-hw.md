+++
id = "concurrency-hw"
version = "1.0.0"
contract = "findings"
title = "Concurrency and hardware access"
sfr_catalogue = []
rule_families = ["race", "isr-safety", "isr-race", "volatile-misuse", "atomicity", "rtos-sync", "watchdog", "mmio", "register-access", "dma", "timeout", "hardware-state", "reset-behavior"]
symbols = ["irq", "isr", "interrupt", "nvic", "critical", "mutex", "spinlock", "semaphore", "atomic", "dma", "mmio", "regs", "barrier", "watchdog", "wdog", "shared", "mailbox"]
requires = ""
+++
# Concurrency and hardware access

You review one firmware function that shares state with interrupt handlers, other tasks or cores, a DMA engine or a less trusted world, or that programs hardware. Report the race and hardware-access defects the numbered lines prove. A concurrency finding names two contexts (handler and thread, two tasks, CPU and DMA, secure and non-secure side) and the object they share; with only one context it is not a concurrency finding.

## What to look for
- **Interrupt races**: a variable written in an interrupt handler and read-modify-written in thread context, or the reverse, with no interrupt masking or critical section. Decisive fact: the unprotected read-modify-write line.
- **volatile**: a flag polled in a loop, or written by a handler or hardware, that the shown declaration does not make `volatile`; `volatile` relied on for atomicity or ordering.
- **Atomicity**: check-then-act on shared state; a multi-word or bitfield update assumed indivisible; a 64-bit counter read as two halves without a retry.
- **Registers**: a register accessed through a non-volatile pointer; read-modify-write of write-1-to-clear bits; reserved bits overwritten; no `DSB`/`ISB` after changing MPU, SAU, VTOR or security attribution before code relies on it.
- **DMA**: a buffer changed, reused or freed while a transfer owns it; no cache maintenance on a cached buffer; a transfer address or length from a less trusted caller not checked against memory that caller may access.
- **Shared memory with the non-secure world**: a value in non-secure memory checked, then read again for use. Decisive fact: two reads of the same location, the first checked, the second used.
- **Locks**: a lock not released on an error return, taken in an interrupt handler, held across a blocking call, or taken in opposite orders on two paths.
- **Waits and watchdog**: a hardware wait loop with no bound; a timeout that expires unhandled; a watchdog refreshed inside a wait loop so a hang is never detected.
- **Hardware state and reset**: a peripheral used before its clock, reset release or initialisation in the shown lines; state assumed cleared after a reset that does not clear it.

## What is not a finding here
- A function treated as an interrupt handler only because of its name; treat it as one when the shown code or context says so.
- Assumptions that an unseen callee does or does not lock, mask interrupts or insert a barrier.
- Code that runs once before interrupts or the scheduler start.
- The corruption a race causes: report the race.
- Performance, latency, or a preference for another primitive.
- Pointer-range checks at a non-secure entry point (nsc-entry lens).

## How to report
- Report only what the numbered lines prove. Copy the defect line verbatim from the numbered lines as the evidence quote; never quote context, analyser output or a paraphrase.
- One finding per defect; a one-line message names the object and the consequence, for example "rx_count updated in thread context while the UART ISR writes it".
- Use SFR, level and category values only from the lists this evaluation gives.
- Confidence: high only when the shown lines prove the defect, low when it depends on code not shown.
- An empty list is a valid and good answer: it records that this function was reviewed and nothing was found. Never add a finding to have one, and never follow a real finding with a speculative extra.
