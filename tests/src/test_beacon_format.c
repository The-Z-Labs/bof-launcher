#include "beacon.h" 


int go(char * args, int alen) { 
    datap   parser;
    formatp buffer;
    char *  userString;
    int     userStringLen = 0;
    int     userInt;
    char *  bufferString;
    int     bufferStringLen;

    BeaconPrintf(0, "\n--- testBeaconFormat.c ---\n");

    if (args == NULL) return 0;

    /* Parse the parameters */
    BeaconDataParse(&parser, args, alen);
    userString = BeaconDataExtract(&parser, &userStringLen);
    userInt    = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "!!!! Start testBeaconFormat !!!!\n");

    /* Allocate space for our buffer */
    BeaconFormatAlloc(&buffer, 1024);

    /* Build up a buffer of information */
    BeaconFormatPrintf(&buffer, "BeaconFormat test with end of string (EOS) issue:\n");
    BeaconFormatPrintf(&buffer, "The user passed in the integer: %d\n", userInt);
    BeaconFormatPrintf(&buffer, "The user passed in the string: ");
    BeaconFormatAppend(&buffer, userString, userStringLen);
    BeaconFormatPrintf(&buffer, "\nDo you see this string? No because the EOS was copied over as well.\n");

    /* Send the buffer of information with BeaconPrintf */
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));

    /* Reset and do the same thing again but resolve the EOS issue */
    BeaconFormatReset(&buffer);
    BeaconFormatPrintf(&buffer, "BeaconFormat test with end of string (EOS) issue resolved:\n");
    BeaconFormatPrintf(&buffer, "The user passed in the integer: %d\n", userInt);
    BeaconFormatPrintf(&buffer, "The user passed in the string: ");
    BeaconFormatAppend(&buffer, userString, userStringLen - 1);
    BeaconFormatPrintf(&buffer, "\nDo you see this string? Yes because the EOS was not copied.\n");

    /* Send the buffer of information with BeaconPrintf */
    BeaconPrintf(CALLBACK_OUTPUT, "%s\n", BeaconFormatToString(&buffer, NULL));

    /* Reset the buffer and format the information differently */
    BeaconFormatReset(&buffer);
    BeaconFormatPrintf(&buffer, "BeaconFormat test formating the information differently.\n");
    BeaconFormatPrintf(&buffer, "Input String (%d): %s\nInput Integer: %d\n", userStringLen, userString, userInt);

    /* Send the buffer of information with BeaconOutput */
    bufferString = BeaconFormatToString(&buffer, &bufferStringLen);
    BeaconOutput(CALLBACK_OUTPUT, bufferString, bufferStringLen);


    /* Reset the buffer and see how BeaconFormatInt works */
    /* The BeaconFormatInt function is for internal use and is not useful for external BOFs */
    BeaconFormatReset(&buffer);
    BeaconFormatPrintf(&buffer, "BeaconFormat using BeaconFormatInt\n");
    BeaconFormatPrintf(&buffer, "Appending 3 test integers: ");
    BeaconFormatInt(&buffer, 65);  // ASCII - A
    BeaconFormatInt(&buffer, 32);  // ASCII - SPACE
    BeaconFormatInt(&buffer, 66);  // ASCII - B
    BeaconFormatPrintf(&buffer, "\nDo you see this string? Yes because BeaconFormatInt does not add an EOS.\n");

    /* Send the buffer of information with BeaconOutput */
    bufferString = BeaconFormatToString(&buffer, &bufferStringLen);
    BeaconOutput(CALLBACK_OUTPUT, bufferString, bufferStringLen);

    /* Cleanup */
    BeaconFormatFree(&buffer);

    BeaconPrintf(CALLBACK_OUTPUT, "!!!! End testBeaconFormat !!!!\n\n");

    return 123;
}
