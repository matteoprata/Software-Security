#include "stdafx.h"
#include "stdio.h"
#undef __analysis_assume
#include <CodeAnalysis\SourceAnnotations.h>

#define BUF_SIZE 100  
#define STR_SIZE 200

void zeroing();


/* I used three different kinds of comments: 
	FIXED WARNING is for code fixed with warnings by prefast 
	FIXED is for code fixed without warnings by prefast
	NOTE are normal comments 
*/

_Ret_opt_cap_(size) char *my_alloc(size_t size) {
	char *ch = (char *)malloc(size);
		
	/* FIXED WARNING: Added if-clause to be sure to dereferenciate a non NULL pointer later on. */
	/* NOTE: Returns null if size is <= 0 or if allocation didn't go through. */
	if (ch == NULL || size <= 0) 
		return NULL;

	/* NOTE: Null first position of the buffer, to check if it is empty later. */
	*ch = NULL;  
	
	/* FIXED WARNING: Changed ch[size] with ch[size-1] since last accessible position is at index size-1. */
	/* FIXED: When size is 0 we may access location ch[-1]. Prefast doesn't give warnings. I fixed it by imposing above to return if size <= 0. */
    ch[size-1] = NULL;
    return ch;
}

HRESULT input([SA_Post(Tainted=SA_Yes)] _Out_cap_(size) char *buf, size_t size) {
	/* FIXED WARNING: gets function isn't proper because it can easily cause buffer overflow. */
	/* NOTE: gets_s and fgets are valid replacements because they allow to specify the number of characters to write. 
	         gets_s(buf, n) writes n-1 characters in buf and and always writes the terminating null character. */
	return (gets_s(buf, size) != NULL) ? SEVERITY_SUCCESS : SEVERITY_ERROR;
}

[returnvalue:SA_Post(Tainted=SA_Yes)] _Ret_opt_cap_c_(STR_SIZE) char *do_read() {
	char *buf = my_alloc(STR_SIZE);
	
	/* FIXED WARNING: Added if-clause to be sure to dereferenciate a non NULL pointer in this function. */
	if (buf == NULL) 
		return NULL; 

	/* FIXED WARNING: Improper format specifier %x for *char, replaced with %p used for pointers. */
	printf("Allocated a string at %p", buf); 

	/* FIXED WARNING: Improper usage of ! operator for function returning HRESULT type, replaced with FAILED macro. */
	if (FAILED(input(buf, STR_SIZE))) {   
		printf("error!");
		exit(-1);
	}
	
	/* FIXED WARNING: Improper usage of = operator, replaced with == used for comparisons. */
	if (*buf == NULL)  
		printf("empty string");
	return buf;
}

void copy_data([SA_Pre(Tainted=SA_Yes)] _In_count_(size1) char *buf1, size_t size1,
               [SA_Post(Tainted=SA_Yes)] _Out_cap_(size2) char *buf2, size_t size2) {
	
	/* FIXED: memcpy(dst, src, count) function does not check for any terminating null character in src buffer.
			  Furthermore count may be larger than size of dst, we may copy src into dst of lower size, thus causing a buffer overflow.
			  In order to solve this I substituted STR_SIZE from original memcpy(buf2, buf1, STR_SIZE) call by the minimum size between buf1 and buf2. */
	/* NOTE: One could decide to substitute memcpy with memcpy_s(dst, dstsize, src, count) to get errors when wrong operations are done. */
	size_t min_size = size1 <= size2 ? size1 : size2;
	memcpy(buf2, buf1, min_size); 

	buf2[size2-1] = NULL;
}

void swap([SA_Post(Tainted=SA_No)] _In_opt_ char *buf1, 
	      [SA_Pre(Tainted=SA_Yes)] _In_opt_ char *buf2) {

	/*NOTE: The function as it is, doesn't swapping pointers. A correct swapping method would be as commented here:
			 char *x = buf1;
			 buf1 = buf2;
		     buf2 = x; 
		     Assuming the programmer is aware of what this swap function really does (pointing both pointers to buf1), it doesn't cause vulnerabilities. */

	char *x = buf1;
    buf2 = buf1;
	buf1 = x;
}

int execute([SA_Pre(Tainted=SA_No)] _In_opt_ char *buf) {
	/* NOTE: Invokes the command processor to execute a command. If command is a null pointer, the function 
	         only checks whether a command processor is available through this function, without invoking any command. */
	return system(buf); 
}

/* NOTE: Add annotation _In_ or _Out_ or _Inout_ wether buf will be read only, written only or both. 
         I expect the function to both read and write in buf. So I would use _Inout_ but I don't have enough informations for now. */
void validate([SA_Pre(Tainted=SA_Yes)][SA_Post(Tainted=SA_No)] char *buf) {

    // This is a magical validation method, which turns tainted data
    // into untainted data, for which the code not shown.
    //
    // A real implementation might for example use a whitelist to filter
    // the string.
}

_Check_return_ int test_ready() { 
	return 1;
}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
	
	char *buf1 = do_read();
	char *buf2 = my_alloc(BUF_SIZE); 
	
	if (buf2 == NULL)
		exit(-1);
	
	zeroing();
	
	/* FIXED WARNING: test_ready() returned a value that wasn't used. */
	/* NOTE: If the purpose of the function is to activly wait until the system is ready one could use while(test_ready()) {} instead. */ 
	if (test_ready()) {

		/* NOTE: buf1 can be null. */
		// ADDED VALIDATION since buf1 can be tainted
		validate(buf1);
		execute(buf1);

    	char* buf3 = do_read();
    	/* NOTE: buf3 can be null. I did the check since I assumed that copy_data doesn't handle null buffers. */
    	if (buf3 == NULL)
			exit(-1);
	
		copy_data(buf3, STR_SIZE, buf2, BUF_SIZE); 
		// ADDED VALIDATION since buf2 can be tainted
		validate(buf2);
		execute(buf2);

		char *buf4 = my_alloc(STR_SIZE);
    	char *buf5 = do_read();
		
		/* NOTE: buf5 or buf4 can be null. This call will set buf5 to buf4 and buf4 to buf4.*/
    	swap(buf4, buf5);
    
		/* NOTE: validate(buf4) is not needed since buf4 is not tainted even after the execution of swap(buf4, buf5) */
    	execute(buf4);
    }
}

// *****************************************************************

void zero(_Out_cap_(len) int *buf, int len)
{
    int i;
	/* FIXED WARNING: Replaced <= operator with < operator. One memory location outside of the bounds of the buffer would be overridden. */
	for(i = 0; i < len; i++) 
        buf[i] = 0;
}

void zeroboth(_Out_cap_(len) int *buf, int len, 
              _Out_cap_(len3) int *buf3, int len3)
{
    int *buf2 = buf;
    int len2 = len;
    zero(buf2, len2);
    zero(buf3, len3);
}

void zeroboth2(_Out_cap_(len) int *buf, int len, 
	           _Out_cap_(len3) int *buf3, int len3) 
{
	/* FIXED: Due to a wrong positioning of the arguments passed to this function call, it would have caused buffer overflow to call zero(buf3, len3) above.  
               Prefast doesn't give warnings. I fixed it by replacing zeroboth(buf, len3, buf3, len) with what shown below. */
	zeroboth(buf, len, buf3, len3);   
}

void zeroing()
{
    int elements[200];
    int oelements[100];
    zeroboth2(elements, 200, oelements, 100);
}
