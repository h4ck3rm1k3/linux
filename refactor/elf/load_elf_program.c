typedef unsigned long __kernel_ulong_t;
typedef __kernel_ulong_t __kernel_size_t;
typedef __kernel_size_t size_t;

typedef struct gfp
{
	gfp(unsigned int);
//	gfp_t  operator | (gfp_t  );
} gfp_t;

//template <class T> T  
typedef const char * string_t;


int memcmp(string_t cs, string_t ct, size_t count);

struct elf64_hdr_type {
	bool operator != (int x);
};

struct elf64_hdr_machine {
	bool operator == (int x);
};

typedef struct elf64_hdr
{	
	elf64_hdr_type e_type;
	elf64_hdr_machine e_machine;
	string_t e_ident;

	struct phentsize {
		bool operator != (int x);
	} e_phentsize;
	
	struct phnum {

	} e_phnum;

	struct phoff {

	} e_phoff;

} elf64_hdr_t;

bool operator < (elf64_hdr::phnum, int x);
bool operator > (elf64_hdr::phnum, long unsigned x);
bool operator * (elf64_hdr::phnum, long unsigned x);

gfp_t  operator | (gfp_t,gfp_t  );

typedef struct location{
	
	struct elf64_hdr elf_ex;
	struct elf64_hdr interp_elf_ex;
} location_t;

struct elf64_phdr
{
};

struct linux_binprm
{
	struct elf64_hdr * buf;
	struct linux_binprm_file {
		struct linux_binprm_file_f_op {
			bool operator ! (void);
			struct mmap_bool {
				bool operator ! (void);
			} mmap;			
		} * f_op;
	} * file;
};

template <class T> T * kmalloc(int s,gfp_t f );
//template <> location_t * kmalloc(int s,gfp_t f ) {}
//location_t * kmalloc(int s,gfp_t f );
//elf64_phdr * kmalloc(int s,gfp_t f );
//void * kmalloc(int s,gfp_t f );


int kernel_read (elf64_phdr elf_phdata, size_t size);
int kernel_read (linux_binprm::linux_binprm_file*,size_t size);
int kernel_read (linux_binprm::linux_binprm_file*&, elf64_hdr::phoff&, elf64_phdr*&, unsigned int&);



static int load_elf_binary(struct linux_binprm *bprm, struct pt_regs *regs)
{
	struct file *interpreter = 0;
	unsigned long load_addr = 0, load_bias = 0;
	int load_addr_set = 0;
	char * elf_interpreter = 0;
	unsigned long error;
	struct elf64_phdr *elf_ppnt, *elf_phdata;
	unsigned long elf_bss, elf_brk;
	int retval, i;
	unsigned int size;
	unsigned long elf_entry;
	unsigned long interp_load_addr = 0;
	unsigned long start_code, end_code, start_data, end_data;
	unsigned long reloc_func_desc __attribute__((unused)) = 0;
	int executable_stack = 0;
	unsigned long def_flags = 0;

	location_t *loc;

	loc = kmalloc<location_t>(sizeof(*loc), ((( gfp_t)0x10u) | (( gfp_t)0x40u) | (( gfp_t)0x80u)));
	if (!loc) {
		retval = -12;
		goto out_ret;
	}


	loc->elf_ex = *((struct elf64_hdr *)bprm->buf);

	retval = -8;

	if (memcmp(loc->elf_ex.e_ident, "\177ELF", 4) != 0)
		goto out;

	if (loc->elf_ex.e_type != 2 && loc->elf_ex.e_type != 3)
		goto out;
	if (!((&loc->elf_ex)->e_machine == 62))
		goto out;
	if (!bprm->file->f_op || !bprm->file->f_op->mmap)
		goto out;


	if (loc->elf_ex.e_phentsize != sizeof(struct elf64_phdr))
		goto out;
	if (loc->elf_ex.e_phnum < 1 ||
		loc->elf_ex.e_phnum > 65536U / sizeof(struct elf64_phdr))
		goto out;
	size = loc->elf_ex.e_phnum * sizeof(struct elf64_phdr);
	retval = -12;
	elf_phdata = kmalloc<elf64_phdr>(size, ((( gfp_t)0x10u) | (( gfp_t)0x40u) | (( gfp_t)0x80u)));
	if (!elf_phdata)
		goto out;

	retval = kernel_read(bprm->file, loc->elf_ex.e_phoff,
			elf_phdata, size);
	if (retval != size) {
		if (retval >= 0)
			retval = -5;
		goto out_free_ph;
	}

	elf_ppnt = elf_phdata;
	elf_bss = 0;
	elf_brk = 0;

	start_code = ~0UL;
	end_code = 0;
	start_data = 0;
	end_data = 0;

	for (i = 0; i < loc->elf_ex.e_phnum; i++) {
		if (elf_ppnt->p_type == 3) {




			retval = -8;
			if (elf_ppnt->p_filesz > 4096 ||
				elf_ppnt->p_filesz < 2)
				goto out_free_ph;

			retval = -12;
			elf_interpreter = kmalloc(elf_ppnt->p_filesz,
						((( gfp_t)0x10u) | (( gfp_t)0x40u) | (( gfp_t)0x80u)));
			if (!elf_interpreter)
				goto out_free_ph;

			retval = kernel_read(bprm->file, elf_ppnt->p_offset,
					elf_interpreter,
					elf_ppnt->p_filesz);
			if (retval != elf_ppnt->p_filesz) {
				if (retval >= 0)
					retval = -5;
				goto out_free_interp;
			}

			retval = -8;
			if (elf_interpreter[elf_ppnt->p_filesz - 1] != '\0')
				goto out_free_interp;

			interpreter = open_exec(elf_interpreter);
			retval = PTR_ERR(interpreter);
			if (IS_ERR(interpreter))
				goto out_free_interp;






			would_dump(bprm, interpreter);

			retval = kernel_read(interpreter, 0, bprm->buf,
					128);
			if (retval != 128) {
				if (retval >= 0)
					retval = -5;
				goto out_free_dentry;
			}


			loc->interp_elf_ex = *((struct elf64_hdr *)bprm->buf);
			break;
		}
		elf_ppnt++;
	}

	elf_ppnt = elf_phdata;
	for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
		if (elf_ppnt->p_type == (0x60000000 + 0x474e551)) {
			if (elf_ppnt->p_flags & 0x1)
				executable_stack = 2;
			else
				executable_stack = 1;
			break;
		}


	if (elf_interpreter) {
		retval = -80;

		if (memcmp(loc->interp_elf_ex.e_ident, "\177ELF", 4) != 0)
			goto out_free_dentry;

		if (!((&loc->interp_elf_ex)->e_machine == 62))
			goto out_free_dentry;
	}


	retval = flush_old_exec(bprm);
	if (retval)
		goto out_free_dentry;


	get_current()->mm->def_flags = def_flags;



	set_personality_64bit();
	if ((executable_stack != 1))
		get_current()->personality |= READ_IMPLIES_EXEC;

	if (!(get_current()->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		get_current()->flags |= 0x00400000;

	setup_new_exec(bprm);



	get_current()->mm->free_area_cache = get_current()->mm->mmap_base;
	get_current()->mm->cached_hole_size = 0;
	retval = setup_arg_pages(bprm, randomize_stack_top((test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12)))),
				executable_stack);
	if (retval < 0) {
		send_sig(9, get_current(), 0);
		goto out_free_dentry;
	}

	get_current()->mm->start_stack = bprm->p;



	for(i = 0, elf_ppnt = elf_phdata;
	    i < loc->elf_ex.e_phnum; i++, elf_ppnt++) {
		int elf_prot = 0, elf_flags;
		unsigned long k, vaddr;

		if (elf_ppnt->p_type != 1)
			continue;

		if (__builtin_expect(!!(elf_brk > elf_bss), 0)) {
			unsigned long nbyte;




			retval = set_brk(elf_bss + load_bias,
					elf_brk + load_bias);
			if (retval) {
				send_sig(9, get_current(), 0);
				goto out_free_dentry;
			}
			nbyte = ((elf_bss) & (((1UL) << 12)-1));
			if (nbyte) {
				nbyte = ((1UL) << 12) - nbyte;
				if (nbyte > elf_brk - elf_bss)
					nbyte = elf_brk - elf_bss;
				if (clear_user((void *)elf_bss +
						load_bias, nbyte)) {





				}
			}
		}

		if (elf_ppnt->p_flags & 0x4)
			elf_prot |= 0x1;
		if (elf_ppnt->p_flags & 0x2)
			elf_prot |= 0x2;
		if (elf_ppnt->p_flags & 0x1)
			elf_prot |= 0x4;

		elf_flags = 0x02 | 0x0800 | 0x1000;

		vaddr = elf_ppnt->p_vaddr;
		if (loc->elf_ex.e_type == 2 || load_addr_set) {
			elf_flags |= 0x10;
		} else if (loc->elf_ex.e_type == 3) {
# 805 "fs/binfmt_elf.c"
			if (get_current()->flags & 0x00400000)
				load_bias = 0;
			else
				load_bias = ((((test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12))) / 3 * 2) - vaddr) & ~(unsigned long)(((1UL) << 12)-1));



		}

		error = elf_map(bprm->file, load_bias + vaddr, elf_ppnt,
				elf_prot, elf_flags, 0);
		if (((unsigned long)(error) >= (test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12))))) {
			send_sig(9, get_current(), 0);
			retval = IS_ERR((void *)error) ?
				PTR_ERR((void*)error) : -22;
			goto out_free_dentry;
		}

		if (!load_addr_set) {
			load_addr_set = 1;
			load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
			if (loc->elf_ex.e_type == 3) {
				load_bias += error -
					((load_bias + vaddr) & ~(unsigned long)(((1UL) << 12)-1));
				load_addr += load_bias;
				reloc_func_desc = load_bias;
			}
		}
		k = elf_ppnt->p_vaddr;
		if (k < start_code)
			start_code = k;
		if (start_data < k)
			start_data = k;






		if (((unsigned long)(k) >= (test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12)))) || elf_ppnt->p_filesz > elf_ppnt->p_memsz ||
			elf_ppnt->p_memsz > (test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12))) ||
			(test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12))) - elf_ppnt->p_memsz < k) {

			send_sig(9, get_current(), 0);
			retval = -22;
			goto out_free_dentry;
		}

		k = elf_ppnt->p_vaddr + elf_ppnt->p_filesz;

		if (k > elf_bss)
			elf_bss = k;
		if ((elf_ppnt->p_flags & 0x1) && end_code < k)
			end_code = k;
		if (end_data < k)
			end_data = k;
		k = elf_ppnt->p_vaddr + elf_ppnt->p_memsz;
		if (k > elf_brk)
			elf_brk = k;
	}

	loc->elf_ex.e_entry += load_bias;
	elf_bss += load_bias;
	elf_brk += load_bias;
	start_code += load_bias;
	end_code += load_bias;
	start_data += load_bias;
	end_data += load_bias;






	retval = set_brk(elf_bss, elf_brk);
	if (retval) {
		send_sig(9, get_current(), 0);
		goto out_free_dentry;
	}
	if (__builtin_expect(!!(elf_bss != elf_brk), 1) && __builtin_expect(!!(padzero(elf_bss)), 0)) {
		send_sig(11, get_current(), 0);
		retval = -14;
		goto out_free_dentry;
	}

	if (elf_interpreter) {
		unsigned long interp_map_addr = 0;

		elf_entry = load_elf_interp(&loc->interp_elf_ex,
					interpreter,
					&interp_map_addr,
					load_bias);
		if (!IS_ERR((void *)elf_entry)) {




			interp_load_addr = elf_entry;
			elf_entry += loc->interp_elf_ex.e_entry;
		}
		if (((unsigned long)(elf_entry) >= (test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12))))) {
			force_sig(11, get_current());
			retval = IS_ERR((void *)elf_entry) ?
				(int)elf_entry : -22;
			goto out_free_dentry;
		}
		reloc_func_desc = interp_load_addr;

		allow_write_access(interpreter);
		fput(interpreter);
		kfree(elf_interpreter);
	} else {
		elf_entry = loc->elf_ex.e_entry;
		if (((unsigned long)(elf_entry) >= (test_ti_thread_flag(current_thread_info(), 29) ? ((get_current()->personality & ADDR_LIMIT_3GB) ? 0xc0000000 : 0xFFFFe000) : ((1UL << 47) - ((1UL) << 12))))) {
			force_sig(11, get_current());
			retval = -22;
			goto out_free_dentry;
		}
	}

	kfree(elf_phdata);

	set_binfmt(&elf_format);


	retval = arch_setup_additional_pages(bprm, !!elf_interpreter);
	if (retval < 0) {
		send_sig(9, get_current(), 0);
		goto out;
	}


	install_exec_creds(bprm);
	retval = create_elf_tables(bprm, &loc->elf_ex,
				load_addr, interp_load_addr);
	if (retval < 0) {
		send_sig(9, get_current(), 0);
		goto out;
	}

	get_current()->mm->end_code = end_code;
	get_current()->mm->start_code = start_code;
	get_current()->mm->start_data = start_data;
	get_current()->mm->end_data = end_data;
	get_current()->mm->start_stack = bprm->p;


	if ((get_current()->flags & 0x00400000) && (randomize_va_space > 1)) {
		get_current()->mm->brk = get_current()->mm->start_brk =
			arch_randomize_brk(get_current()->mm);



	}


	if (get_current()->personality & MMAP_PAGE_ZERO) {




		error = vm_mmap(((void *)0), 0, ((1UL) << 12), 0x1 | 0x4,
				0x10 | 0x02, 0);
	}
# 981 "fs/binfmt_elf.c"
	elf_common_init(&get_current()->thread, regs, 0);


	start_thread(regs, elf_entry, bprm->p);
	retval = 0;
out:
	kfree(loc);
out_ret:
	return retval;


out_free_dentry:
	allow_write_access(interpreter);
	if (interpreter)
		fput(interpreter);
out_free_interp:
	kfree(elf_interpreter);
out_free_ph:
	kfree(elf_phdata);
	goto out;
}


