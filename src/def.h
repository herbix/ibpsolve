#ifndef _DEF_H_
#define _DEF_H_


#ifdef _DEBUG
#define ASSERT(cond) \
	if(!(cond)) {   \
		printf("'%s' not satisfied at line %d.\n", #cond, __LINE__);  \
		exit(-1); \
	}
#else
#define ASSERT(cond) if(cond){}
#endif

#define bool		char
#define true		1
#define false		0

#endif
