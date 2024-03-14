name bbrb_rtr
neighbor te1/3/0 boza_rtr
neighbor te1/3/1 rozb_rtr
port te1/3 ecmp te1/3/0 te1/3/1
neighbor te1/1/0 goza_rtr
neighbor te1/1/1 pozb_rtr
port te1/1 ecmp te1/1/0 te1/1/1
neighbor te6/3/0 roza_rtr
neighbor te6/3/1 bozb_rtr
neighbor te6/3/2 yozb_rtr
port te6/3 ecmp te6/3/0 te6/3/1 te6/3/2
neighbor te7/4 yoza_rtr
neighbor te7/1 bbra_rtr
neighbor te7/2/0 poza_rtr
neighbor te7/2/1 soza_rtr
neighbor te7/2/2 gozb_rtr
neighbor te7/2/3 cozb_rtr
port te7/2 ecmp te7/2/0 te7/2/1 te7/2/2 te7/2/3
neighbor te6/1/0 coza_rtr
neighbor te6/1/1 sozb_rtr
port te6/1 ecmp te6/1/0 te6/1/1
