/* Define helper symbols to inform Cooja about start addresses and sizes
   of segments. */
SECTIONS{
    cooja_bssSize = SIZEOF(.bss);
    cooja_dataSize = SIZEOF(.data);
    cooja_bssStart = ADDR(.bss);
    cooja_dataStart = ADDR(.data);
    /* Relocated like the start addresses, unlike the absolute sizes. */
    cooja_bssEnd = ADDR(.bss) + SIZEOF(.bss);
    cooja_dataEnd = ADDR(.data) + SIZEOF(.data);
}
INSERT AFTER .bss;
