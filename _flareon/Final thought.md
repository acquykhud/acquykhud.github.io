---
path: ""
type: posts
values:
layout: article
sharing: true
license: false
aside:
    toc: false
show_edit_on_github: false
show_subscribe: false
pageview: true
title: Final thoughts
tag: flare-on
excerpt: Cảm nhận của mình về flare-on lần này.
---
# Final thoughts

Đây là lần thứ hai mình tham gia, và là lần đầu tiên mình giải được đủ các challenge của `Flare-on CTF`, nên cảm thấy rất vui. Vui vì cuối cùng mình cũng có được cái huy hiệu của `Flare-on`, nhưng quan trọng hơn cả là mình cảm thấy trong một năm qua, mình đã tiến bộ hơn nhiều.

Sau hơn một tháng ngồi làm các challenge này, mình có một số cảm nhận, cũng như một số mẹo nhỏ cho bạn đọc:

- Cấu trúc file `PE` là kiến thức mà mọi người chơi Reverse Engineer và  Malware Analyst nên học. Ví dụ như ở bài 2 và bài 11, mình đã vận dụng kiến thức về file `PE` để có thể sửa lại file bị corrupt.
- `Reflective DLL Injection`, cũng giống như trên, là một kỹ thuật được dùng nhiều trong malware, vì nó khó bị detect hơn so với các phương thức inject khác, kỹ thuật này được sử dụng ở bài 9, và bài 11.
- `windbg` là một debugger rất mạnh, có thể script nữa. Thật sự mà nói, trong khoảng thời gian chơi RE gần 2 năm, mình chưa bao giờ dùng `windbg`, mình toàn coi tutorial `RE` của anh `kienmanowar` rồi dùng `x64dbg` vì nó có giao diện đẹp, bấm chuột click click, dễ xài hơn. Ở bài 9, mình phải tập sử dụng `windbg` để debug window kernel và lấy `password` (đây cũng là lần đầu tiên mình debug windows kernel).
- Khi làm các công việc lặp đi lặp lại nhiều lần, hãy viết `script` nếu có thể. Mình đã viết `script` cho `windbg`, `gdb` ở bài 11, bài 9 và bài 10, giúp tiết kiệm rất nhiều thời gian.
- `"Khi bạn đã nhìn vào một thứ quá lâu mà vẫn không thấy gì, hãy lùi lại một bước để nhìn nó ở một góc độ khác"` - anh `Mạnh Luật (l4w)` said. Điều này mình thấy rất đúng. Mình đã dùng tới tận 12 ngày để giải bài cuối cùng, nhưng trong đó, 11 ngày đầu, mình chỉ ngồi `RE` một đống `DLL`. Nhận thấy cách làm này không ổn, mình đã chuyển sang góc nhìn khác :arrow_right: dùng `procmon` để quan sát mọi thứ. Và, ... mình chỉ tốn chưa tới 12 tiếng để tìm ra flag cho bài cuối ! (Nếu dùng `wireshark` bạn đọc cũng sẽ thấy được program làm gì đó, từ đó trace ngược lại và tìm ra flag).
- Khi gặp source code bị `obfuscate`, hãy cố gắng tìm các pattern trong code, và dùng `regex` để `rename` các biến, các hàm ... thay vì dùng `find and replace` (bài 6).
- Monitor các hàm `API` để hiểu được flow program cũng là một cách hay, mình đã dùng cách này ở bài 7, và bài 10.
- Khi `RE` các hàm lớn, có thể nhìn `input` và `output` để đoán xem hàm đó là gì.
- Khi `RE` các hàm có rất nhiều phép `xor, rotate, shift`, khả năng cao đó là hàm của một thuật toán `crypto` hoặc hàm `hash` nào đó. Dùng plugin `findcrypt` trong IDA hoặc google các hằng số tìm thấy trong program để biết được hàm đó là gì.

Cuối cùng, xin cảm ơn `Fireeye` đã tổ chức một kỳ `CTF` rất chất lượng cho những người chơi `Reverse Engineer` ! Đồng thời mình cũng cảm ơn tất cả các bạn đọc đã bỏ ra thời gian quý giá để đọc tới đây, hi vọng mọi người sẽ thích bài này và ủng hộ các bài blog mà mình sẽ viết trong thời gian tiếp theo ^^!

~~ Trung ~~
