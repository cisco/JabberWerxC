/**
 * Copyrights
 *
 * Portions created or assigned to Cisco Systems, Inc. are
 * Copyright (c) 2010-2015 Cisco Systems, Inc.  All Rights Reserved.
 * See LICENSE for details.
 */

#include "fct.h"

#include <jabberwerx/util/str.h>


FCTMF_SUITE_BGN(str_test)
{
    FCT_TEST_BGN(jw_str_atoi)
    {
        fct_chk_eq_int(jw_atoi("24", 0), 24);
        fct_chk_eq_int(jw_atoi("-42", 0), -42);
        fct_chk_eq_int(jw_atoi("", 0), 0);
        fct_chk_eq_int(jw_atoi(NULL, 0), 0);

        fct_chk_eq_int(jw_atoi("24", 5), 24);
        fct_chk_eq_int(jw_atoi("-42", 5), -42);
        fct_chk_eq_int(jw_atoi("", 5), 0);
        fct_chk_eq_int(jw_atoi(NULL, 5), 5);
    } FCT_TEST_END()
    
    FCT_TEST_BGN(jw_str_compare)
    {
        char *str1, *str2;
        
        str1 = str2 = "a test string";
        fct_chk(jw_strcmp(str1, str2) == 0);
        fct_chk(jw_strcasecmp(str1, str2) == 0);
        str2 = "b test string";
        fct_chk(jw_strcmp(str1, str2) < 0);
        fct_chk(jw_strcasecmp(str1, str2) < 0);
        str1 = "c test";
        fct_chk(jw_strcmp(str1, str2) > 0);
        fct_chk(jw_strcasecmp(str1, str2) > 0);
        
        str1 = "a test string";
        str2 = "A test String";
        fct_chk(jw_strcmp(str1, str2) > 0);
        fct_chk(jw_strcasecmp(str1, str2) == 0);
        
        fct_chk(jw_strcmp(NULL, NULL) == 0);
        fct_chk(jw_strcasecmp(NULL, NULL) == 0);
        
        fct_chk(jw_strcmp(str1, NULL) > 0);
        fct_chk(jw_strcasecmp(str1, NULL) > 0);

        fct_chk(jw_strcmp(NULL, str2) < 0);
        fct_chk(jw_strcasecmp(NULL, str2) < 0);
    } FCT_TEST_END()
    
    FCT_TEST_BGN(jw_str_ncompare)
    {
        char *str1, *str2, *str2case;
        
        str1 = str2 = "test string alpha";
        str2case = "Test String AlphA";
        fct_chk(jw_strncmp(str1, str2, 17) == 0);
        fct_chk(jw_strncasecmp(str1, str2, 17) == 0);
        fct_chk(jw_strncasecmp(str1, str2case, 17) == 0);
        
        str2 = "test string beta";
        str2case = "Test String BetA";
        fct_chk(jw_strncmp(str1, str2, 17) < 0);
        fct_chk(jw_strncasecmp(str1, str2case, 17) < 0);
        
        str2 = "test string al";
        str2case = "Test String Al";
        fct_chk(jw_strncmp(str1, str2, 17) > 0);
        fct_chk(jw_strncmp(str1, str2case, 17) > 0);
        
        fct_chk(jw_strncmp(NULL, NULL, 10) == 0);
        fct_chk(jw_strncasecmp(NULL, NULL, 10) == 0);
        fct_chk(jw_strncmp(str1, NULL, 10) > 0);
        fct_chk(jw_strncasecmp(str1, NULL, 10) > 0);
        fct_chk(jw_strncmp(NULL, str2, 10) < 0);
        fct_chk(jw_strncasecmp(NULL, str2, 10) < 0);
    } FCT_TEST_END()
    
    FCT_TEST_BGN(jw_str_length)
    {
        char *str;
        
        str = "a test string";
        fct_chk_eq_int(jw_strlen(str), 13);
        
        str = "";
        fct_chk_eq_int(jw_strlen(str), 0);
        
        str = "another test string";
        fct_chk_eq_int(jw_strlen(str), 19);
        
        fct_chk_eq_int(jw_strlen(NULL), 0);

        str = "a test string";
        fct_chk_eq_int(jw_strnlen(str, 13), 13);
        
        str = "a test string";
        fct_chk_eq_int(jw_strnlen(str, 17), 13);
        
        str = "";
        fct_chk_eq_int(jw_strnlen(str, 4), 0);
        
        str = "another test string";
        fct_chk_eq_int(jw_strnlen(str, 12), 12);
        
        fct_chk_eq_int(jw_strnlen(NULL, 4), 0);
    } FCT_TEST_END()
} FCTMF_SUITE_END()
