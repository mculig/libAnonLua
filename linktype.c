/*
 * linktype.c
 *
 *  Created on: Jul 20, 2019
 *      Author: mislav
 */

#include "linktype.h"


//Push all the different header link layer types and set them as globals in Lua
//Link types are loaded from a CSV, making it possible to update them easily should new link types come out (they probably will)
void setHeaderLinkTypeValues(lua_State *L) {
	FILE *fp;
	char linktype_name[50];
	int linktype_id;

	fp=fopen("linktypes.csv", "r"); //Open file
	if(fp==NULL) //If it fails, return
	{
		printf("ERROR: Failed to read link types from linktypes.csv file!\n");
		fclose(fp);
		return;
	}

	//Read the file
	while(fscanf(fp,"%[^,],%d\n",linktype_name, &linktype_id)!=EOF)
	{
		//Push the values to the Lua stack, then set them as named constants
		lua_pushnumber(L, linktype_id);
		lua_setfield(L, -2, linktype_name);
	}

	fclose(fp);
}
