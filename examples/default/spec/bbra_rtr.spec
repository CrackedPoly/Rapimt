name bbra_rtr
neighbor te1/4/0 rozb_rtr
neighbor te1/4/1 boza_rtr
port te1/4 ecmp te1/4/0 te1/4/1
neighbor te1/3/0 bozb_rtr
neighbor te1/3/1 roza_rtr
neighbor te1/3/2 yozb_rtr
port te1/3 ecmp te1/3/0 te1/3/1 te1/3/2
neighbor te6/1/0 gozb_rtr
neighbor te6/1/1 cozb_rtr
neighbor te6/1/2 soza_rtr
neighbor te6/1/3 poza_rtr
port te6/1 ecmp te6/1/0 te6/1/1 te6/1/2 te6/1/3
neighbor te6/3 yoza_rtr
neighbor te7/1 bbrb_rtr
neighbor te7/2/0 sozb_rtr
neighbor te7/2/1 coza_rtr
port te7/2 ecmp te7/2/0 te7/2/1
neighbor te7/3/0 pozb_rtr
neighbor te7/3/1 goza_rtr
port te7/3 ecmp te7/3/0 te7/3/1
