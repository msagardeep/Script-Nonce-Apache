#include "httpd.h"
#include "http_config.h"
#include "apr_buckets.h"
#include "apr_general.h"
#include "apr_lib.h"
#include "util_filter.h"
#include "http_request.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <http_core.h>
#include <time.h>

// Filter Name
static const char nonce_module_name[]="ScriptNonce";

// Module Name
module AP_MODULE_DECLARE_DATA script_nonce_module;

// Configuration for the filter
typedef struct
{
    int isEnabled;
} 
ScriptNonceConf;

// Server configuration for the script nonce filter
static void *ScriptNonceCreateServerConf(apr_pool_t *p, server_rec *s)
{
        ScriptNonceConf *conf = apr_pcalloc(p, sizeof(ScriptNonceConf));
        conf->isEnabled = 0;
        return conf;
}

// Insert Filter
static void NonceFilterInsertFilter(request_rec *r)
{
	// check whether the script nonce filter is enabled
        ScriptNonceConf *conf = ap_get_module_config(r->server->module_config, &script_nonce_module);
        if(!conf->isEnabled)
                return;

	// if enabled, add the output filter to the module
    	ap_add_output_filter(nonce_module_name,NULL,r,r->connection);
}

// Output filter processing 
static apr_status_t NonceFilterOutFilter(ap_filter_t *filter, apr_bucket_brigade *bb_in)
{
	// Get the request record
    	request_rec *rec = filter->r;

	// Get the connection record
    	conn_rec *con = rec->connection;

    	apr_bucket *b_in;
    	apr_bucket_brigade *bb_out;

	// Create the output bucket brigade
    	bb_out = apr_brigade_create(rec->pool, con->bucket_alloc);

	// Set the Content Security Policy in the response header
	srandom(time(NULL));
	char nonce[20], value[40];
	sprintf(nonce, "%ld", random());
	strcpy(value,"script-nonce ");
	strcat(value, nonce);
	apr_table_setn(rec->headers_out, "Content-Security-Policy", value);

	// Loop on all the buckets in the input bucket brigade
    	for (b_in = APR_BRIGADE_FIRST(bb_in); b_in != APR_BRIGADE_SENTINEL(bb_in); b_in = APR_BUCKET_NEXT(b_in))
    	{
        	char *old_buff;
        	apr_size_t len;
        	char *new_buff;
        	apr_bucket *b_out;

        	if(APR_BUCKET_IS_EOS(b_in))
        	{
        		apr_bucket *b_eos = apr_bucket_eos_create(con->bucket_alloc);
        		APR_BRIGADE_INSERT_TAIL(bb_out, b_eos);
        		continue;
        	}

		// read data from the bucket
		apr_bucket_read(b_in, &old_buff, &len, APR_BLOCK_READ);
		new_buff = apr_bucket_alloc(len, con->bucket_alloc);

		// search for the nonce
		char *str = NULL;
		char *s = old_buff;
		int i = 0, j = 0;

		while( (str = strstr(s,"nonce")) != NULL)
		{
			char *p = str - 1;
			str = str + 5;

			if(p[0] == '-')
				while(str[0] == ' ') 
					str++;
			if(p[0] == ' ')
			{
				size_t sz = strcspn(str, "\"") ;
				str = str + sz + 1;
			}

			while(s != str)
			{
				new_buff[j++] = old_buff[i++];
				s++;
			}

			char *nonce_str = NULL;

			// check if there is a valid placeholder, replace that
			if( (nonce_str = strstr(str,"aaaaaaaaaa")) == str )
			{
				sprintf(&new_buff[j], "%s", nonce);
				j = j + strlen(nonce);
				size_t sz = strcspn(str, "\"");
				s = s + sz;
				i = i + sz;
			}
			// if no valid placeholder, just copy
			else
			{
				while(old_buff[i] != '"')
				{
					new_buff[j++] = old_buff[i++];
					s++;
				}
			}

			str = NULL;
		}

		while(i<len)
			new_buff[j++] = old_buff[i++];
		new_buff[j] = '\0';

		// create the output bucket
                b_out = apr_bucket_heap_create(new_buff, len, apr_bucket_free, con->bucket_alloc);

		//insert the bucket at the end of the output bucket brigade
		APR_BRIGADE_INSERT_TAIL(bb_out, b_out);				
        }

	// cleanup the input bucket brigade
    	apr_brigade_cleanup(bb_in);

	// pass the new bucket brigade to the next filter in the chain
    	return ap_pass_brigade(filter->next, bb_out);
}

// Enable the script nonce filter
static const char *ScriptNonceEnable(cmd_parms *cmd, void *dummy, int arg)
{
        ScriptNonceConf *conf = ap_get_module_config(cmd->server->module_config, &script_nonce_module);
        conf->isEnabled = arg;
        return NULL;
}

static const command_rec NonceFilterCmds[] =
{
        AP_INIT_FLAG("ScriptNonce", ScriptNonceEnable, NULL, RSRC_CONF, "Run nonce filter"),
        {NULL}
};

// Register the script nonce module as a hook
static void NonceFilterRegisterHooks(apr_pool_t *p)
{
    	ap_hook_insert_filter(NonceFilterInsertFilter, NULL, NULL, APR_HOOK_MIDDLE);
    	ap_register_output_filter(nonce_module_name, NonceFilterOutFilter, NULL, AP_FTYPE_RESOURCE);
}

// Declare the module
module AP_MODULE_DECLARE_DATA script_nonce_module =
{
    	STANDARD20_MODULE_STUFF,
    	NULL,
	NULL,
	ScriptNonceCreateServerConf,		// Configuration record for the host
	NULL,
	NonceFilterCmds,			// Configuration directives
	NonceFilterRegisterHooks
};
