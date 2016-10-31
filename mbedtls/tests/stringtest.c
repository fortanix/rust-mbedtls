/*
 * Tests for various standard string routines in C.
 * 
 * Written in 2016 by Jethro G. Beekman
 * 
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 * 
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <string.h>
#include <assert.h>

int main() {
	// strlen:
	assert(strlen("")==0);
	assert(strlen("X")==1);
	assert(strlen("XX")==2);
	assert(strlen("XXX")==3);

	// strcmp/strncmp various test cases:
	// - same len, same last char
	// - same len, different last char
	// - 1st 1~2 shorter, same until len(s1)
	// - 1st 1~2 shorter, different at len(s1)
	// - 2nd 1~2 shorter, same until len(s2)
	// - 2nd 1~2 shorter, different at len(s2)
	assert(strcmp("","")==0);
	assert(strcmp("","X")<0);
	assert(strcmp("","XX")<0);
	assert(strcmp("YX","X")>0);
	assert(strcmp("YXX","X")>0);
	assert(strcmp("X","")>0);
	assert(strcmp("X","Y")<0);
	assert(strcmp("X","YX")<0);
	assert(strcmp("X","YXX")<0);
	assert(strcmp("X","X")==0);
	assert(strcmp("X","XX")<0);
	assert(strcmp("X","XXX")<0);
	assert(strcmp("XYX","XX")>0);
	assert(strcmp("XYXX","XX")>0);
	assert(strcmp("XX","")>0);
	assert(strcmp("XX","X")>0);
	assert(strcmp("XX","XY")<0);
	assert(strcmp("XX","XYX")<0);
	assert(strcmp("XX","XYXX")<0);
	assert(strcmp("XX","XX")==0);
	assert(strcmp("XX","XXX")<0);
	assert(strcmp("XX","XXXX")<0);
	assert(strcmp("XXYX","XXX")>0);
	assert(strcmp("XXYXX","XXX")>0);
	assert(strcmp("XXX","X")>0);
	assert(strcmp("XXX","XX")>0);
	assert(strcmp("XXX","XXY")<0);
	assert(strcmp("XXX","XXYX")<0);
	assert(strcmp("XXX","XXYXX")<0);
	assert(strcmp("XXX","XXX")==0);
	assert(strcmp("XXX","XXXX")<0);
	assert(strcmp("XXX","XXXXX")<0);
	assert(strcmp("XXXX","XX")>0);
	assert(strcmp("XXXX","XXX")>0);
	assert(strcmp("XXXXX","XXX")>0);

	assert(strncmp("","",-2)==0);
	assert(strncmp("","",-1)==0);
	assert(strncmp("","",2)==0);
	assert(strncmp("","",1)==0);
	assert(strncmp("","",0)==0);
	assert(strncmp("","X",-2)<0);
	assert(strncmp("","X",-1)<0);
	assert(strncmp("","X",3)<0);
	assert(strncmp("","X",2)<0);
	assert(strncmp("","X",1)<0);
	assert(strncmp("","X",0)==0);
	assert(strncmp("","XX",-2)<0);
	assert(strncmp("","XX",-1)<0);
	assert(strncmp("","XX",4)<0);
	assert(strncmp("","XX",3)<0);
	assert(strncmp("","XX",2)<0);
	assert(strncmp("","XX",1)<0);
	assert(strncmp("","XX",0)==0);
	assert(strncmp("YX","X",-1)>0);
	assert(strncmp("YX","X",4)>0);
	assert(strncmp("YX","X",3)>0);
	assert(strncmp("YX","X",2)>0);
	assert(strncmp("YX","X",1)>0);
	assert(strncmp("YX","X",0)==0);
	assert(strncmp("YXX","X",-1)>0);
	assert(strncmp("YXX","X",5)>0);
	assert(strncmp("YXX","X",4)>0);
	assert(strncmp("YXX","X",3)>0);
	assert(strncmp("YXX","X",2)>0);
	assert(strncmp("YXX","X",1)>0);
	assert(strncmp("YXX","X",0)==0);
	assert(strncmp("X","",-2)>0);
	assert(strncmp("X","",-1)>0);
	assert(strncmp("X","",3)>0);
	assert(strncmp("X","",2)>0);
	assert(strncmp("X","",1)>0);
	assert(strncmp("X","",0)==0);
	assert(strncmp("X","Y",-1)<0);
	assert(strncmp("X","Y",3)<0);
	assert(strncmp("X","Y",2)<0);
	assert(strncmp("X","Y",1)<0);
	assert(strncmp("X","Y",0)==0);
	assert(strncmp("X","YX",-1)<0);
	assert(strncmp("X","YX",4)<0);
	assert(strncmp("X","YX",3)<0);
	assert(strncmp("X","YX",2)<0);
	assert(strncmp("X","YX",1)<0);
	assert(strncmp("X","YX",0)==0);
	assert(strncmp("X","YXX",-1)<0);
	assert(strncmp("X","YXX",5)<0);
	assert(strncmp("X","YXX",4)<0);
	assert(strncmp("X","YXX",3)<0);
	assert(strncmp("X","YXX",2)<0);
	assert(strncmp("X","YXX",1)<0);
	assert(strncmp("X","YXX",0)==0);
	assert(strncmp("X","X",-1)==0);
	assert(strncmp("X","X",3)==0);
	assert(strncmp("X","X",2)==0);
	assert(strncmp("X","X",1)==0);
	assert(strncmp("X","X",0)==0);
	assert(strncmp("X","XX",-1)<0);
	assert(strncmp("X","XX",4)<0);
	assert(strncmp("X","XX",3)<0);
	assert(strncmp("X","XX",2)<0);
	assert(strncmp("X","XX",1)==0);
	assert(strncmp("X","XX",0)==0);
	assert(strncmp("X","XXX",-1)<0);
	assert(strncmp("X","XXX",5)<0);
	assert(strncmp("X","XXX",4)<0);
	assert(strncmp("X","XXX",3)<0);
	assert(strncmp("X","XXX",2)<0);
	assert(strncmp("X","XXX",1)==0);
	assert(strncmp("X","XXX",0)==0);
	assert(strncmp("XYX","XX",5)>0);
	assert(strncmp("XYX","XX",4)>0);
	assert(strncmp("XYX","XX",3)>0);
	assert(strncmp("XYX","XX",2)>0);
	assert(strncmp("XYX","XX",1)==0);
	assert(strncmp("XYX","XX",0)==0);
	assert(strncmp("XYXX","XX",6)>0);
	assert(strncmp("XYXX","XX",5)>0);
	assert(strncmp("XYXX","XX",4)>0);
	assert(strncmp("XYXX","XX",3)>0);
	assert(strncmp("XYXX","XX",2)>0);
	assert(strncmp("XYXX","XX",1)==0);
	assert(strncmp("XYXX","XX",0)==0);
	assert(strncmp("XX","",-2)>0);
	assert(strncmp("XX","",-1)>0);
	assert(strncmp("XX","",4)>0);
	assert(strncmp("XX","",3)>0);
	assert(strncmp("XX","",2)>0);
	assert(strncmp("XX","",1)>0);
	assert(strncmp("XX","",0)==0);
	assert(strncmp("XX","X",-1)>0);
	assert(strncmp("XX","X",4)>0);
	assert(strncmp("XX","X",3)>0);
	assert(strncmp("XX","X",2)>0);
	assert(strncmp("XX","X",1)==0);
	assert(strncmp("XX","X",0)==0);
	assert(strncmp("XX","XY",4)<0);
	assert(strncmp("XX","XY",3)<0);
	assert(strncmp("XX","XY",2)<0);
	assert(strncmp("XX","XY",1)==0);
	assert(strncmp("XX","XY",0)==0);
	assert(strncmp("XX","XYX",5)<0);
	assert(strncmp("XX","XYX",4)<0);
	assert(strncmp("XX","XYX",3)<0);
	assert(strncmp("XX","XYX",2)<0);
	assert(strncmp("XX","XYX",1)==0);
	assert(strncmp("XX","XYX",0)==0);
	assert(strncmp("XX","XYXX",6)<0);
	assert(strncmp("XX","XYXX",5)<0);
	assert(strncmp("XX","XYXX",4)<0);
	assert(strncmp("XX","XYXX",3)<0);
	assert(strncmp("XX","XYXX",2)<0);
	assert(strncmp("XX","XYXX",1)==0);
	assert(strncmp("XX","XYXX",0)==0);
	assert(strncmp("XX","XX",4)==0);
	assert(strncmp("XX","XX",3)==0);
	assert(strncmp("XX","XX",2)==0);
	assert(strncmp("XX","XX",1)==0);
	assert(strncmp("XX","XX",0)==0);
	assert(strncmp("XX","XXX",5)<0);
	assert(strncmp("XX","XXX",4)<0);
	assert(strncmp("XX","XXX",3)<0);
	assert(strncmp("XX","XXX",2)==0);
	assert(strncmp("XX","XXX",1)==0);
	assert(strncmp("XX","XXX",0)==0);
	assert(strncmp("XX","XXXX",6)<0);
	assert(strncmp("XX","XXXX",5)<0);
	assert(strncmp("XX","XXXX",4)<0);
	assert(strncmp("XX","XXXX",3)<0);
	assert(strncmp("XX","XXXX",2)==0);
	assert(strncmp("XX","XXXX",1)==0);
	assert(strncmp("XX","XXXX",0)==0);
	assert(strncmp("XXYX","XXX",6)>0);
	assert(strncmp("XXYX","XXX",5)>0);
	assert(strncmp("XXYX","XXX",4)>0);
	assert(strncmp("XXYX","XXX",3)>0);
	assert(strncmp("XXYX","XXX",2)==0);
	assert(strncmp("XXYX","XXX",1)==0);
	assert(strncmp("XXYXX","XXX",7)>0);
	assert(strncmp("XXYXX","XXX",6)>0);
	assert(strncmp("XXYXX","XXX",5)>0);
	assert(strncmp("XXYXX","XXX",4)>0);
	assert(strncmp("XXYXX","XXX",3)>0);
	assert(strncmp("XXYXX","XXX",2)==0);
	assert(strncmp("XXYXX","XXX",1)==0);
	assert(strncmp("XXX","X",-1)>0);
	assert(strncmp("XXX","X",5)>0);
	assert(strncmp("XXX","X",4)>0);
	assert(strncmp("XXX","X",3)>0);
	assert(strncmp("XXX","X",2)>0);
	assert(strncmp("XXX","X",1)==0);
	assert(strncmp("XXX","X",0)==0);
	assert(strncmp("XXX","XX",5)>0);
	assert(strncmp("XXX","XX",4)>0);
	assert(strncmp("XXX","XX",3)>0);
	assert(strncmp("XXX","XX",2)==0);
	assert(strncmp("XXX","XX",1)==0);
	assert(strncmp("XXX","XX",0)==0);
	assert(strncmp("XXX","XXY",5)<0);
	assert(strncmp("XXX","XXY",4)<0);
	assert(strncmp("XXX","XXY",3)<0);
	assert(strncmp("XXX","XXY",2)==0);
	assert(strncmp("XXX","XXY",1)==0);
	assert(strncmp("XXX","XXYX",6)<0);
	assert(strncmp("XXX","XXYX",5)<0);
	assert(strncmp("XXX","XXYX",4)<0);
	assert(strncmp("XXX","XXYX",3)<0);
	assert(strncmp("XXX","XXYX",2)==0);
	assert(strncmp("XXX","XXYX",1)==0);
	assert(strncmp("XXX","XXYXX",7)<0);
	assert(strncmp("XXX","XXYXX",6)<0);
	assert(strncmp("XXX","XXYXX",5)<0);
	assert(strncmp("XXX","XXYXX",4)<0);
	assert(strncmp("XXX","XXYXX",3)<0);
	assert(strncmp("XXX","XXYXX",2)==0);
	assert(strncmp("XXX","XXYXX",1)==0);
	assert(strncmp("XXX","XXX",5)==0);
	assert(strncmp("XXX","XXX",4)==0);
	assert(strncmp("XXX","XXX",3)==0);
	assert(strncmp("XXX","XXX",2)==0);
	assert(strncmp("XXX","XXX",1)==0);
	assert(strncmp("XXX","XXXX",6)<0);
	assert(strncmp("XXX","XXXX",5)<0);
	assert(strncmp("XXX","XXXX",4)<0);
	assert(strncmp("XXX","XXXX",3)==0);
	assert(strncmp("XXX","XXXX",2)==0);
	assert(strncmp("XXX","XXXX",1)==0);
	assert(strncmp("XXX","XXXXX",7)<0);
	assert(strncmp("XXX","XXXXX",6)<0);
	assert(strncmp("XXX","XXXXX",5)<0);
	assert(strncmp("XXX","XXXXX",4)<0);
	assert(strncmp("XXX","XXXXX",3)==0);
	assert(strncmp("XXX","XXXXX",2)==0);
	assert(strncmp("XXX","XXXXX",1)==0);
	assert(strncmp("XXXX","XX",6)>0);
	assert(strncmp("XXXX","XX",5)>0);
	assert(strncmp("XXXX","XX",4)>0);
	assert(strncmp("XXXX","XX",3)>0);
	assert(strncmp("XXXX","XX",2)==0);
	assert(strncmp("XXXX","XX",1)==0);
	assert(strncmp("XXXX","XX",0)==0);
	assert(strncmp("XXXX","XXX",6)>0);
	assert(strncmp("XXXX","XXX",5)>0);
	assert(strncmp("XXXX","XXX",4)>0);
	assert(strncmp("XXXX","XXX",3)==0);
	assert(strncmp("XXXX","XXX",2)==0);
	assert(strncmp("XXXX","XXX",1)==0);
	assert(strncmp("XXXXX","XXX",7)>0);
	assert(strncmp("XXXXX","XXX",6)>0);
	assert(strncmp("XXXXX","XXX",5)>0);
	assert(strncmp("XXXXX","XXX",4)>0);
	assert(strncmp("XXXXX","XXX",3)==0);
	assert(strncmp("XXXXX","XXX",2)==0);
	assert(strncmp("XXXXX","XXX",1)==0);

	// strncpy various test cases:
	// - n is one less than strlen
	// - n is strlen
	// - n is one more than strlen
	{char buffer[16]="---------------";assert(strncpy(buffer,"",1)==buffer);assert(buffer[0]==0&&buffer[1]==45&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"",0)==buffer);assert(buffer[0]==45&&buffer[1]==45&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"X",2)==buffer);assert(buffer[0]==88&&buffer[1]==0&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"X",1)==buffer);assert(buffer[0]==88&&buffer[1]==45&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"X",0)==buffer);assert(buffer[0]==45&&buffer[1]==45&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"XX",3)==buffer);assert(buffer[0]==88&&buffer[1]==88&&buffer[2]==0&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"XX",2)==buffer);assert(buffer[0]==88&&buffer[1]==88&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"XX",1)==buffer);assert(buffer[0]==88&&buffer[1]==45&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"XXX",4)==buffer);assert(buffer[0]==88&&buffer[1]==88&&buffer[2]==88&&buffer[3]==0&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"XXX",3)==buffer);assert(buffer[0]==88&&buffer[1]==88&&buffer[2]==88&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}
	{char buffer[16]="---------------";assert(strncpy(buffer,"XXX",2)==buffer);assert(buffer[0]==88&&buffer[1]==88&&buffer[2]==45&&buffer[3]==45&&buffer[4]==45&&buffer[5]==45&&buffer[6]==45&&buffer[7]==45&&buffer[8]==45&&buffer[9]==45&&buffer[10]==45&&buffer[11]==45&&buffer[12]==45&&buffer[13]==45&&buffer[14]==45&&buffer[15]==0);}

	return 0;
}
