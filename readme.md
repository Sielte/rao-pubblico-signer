## Introduzione

Il seguente progetto mette a disposizione dei R.A.O. pubblici uno strumento per firmare le richieste di identificazione SPID.


## Utilizzo dell’applicativo

### POST/init
Per l’inserimento di un nuovo Security Officer (Amministratore del R.A.O. pubblico).

Input (form-data): 
*	username [type:string] (Codice fiscale S.O./ADMIN R.A.O.)
*	entity [type:string] (Codice IPA)


Output:
*	JSON {‘statusCode’: 200, ‘message’: ‘124578’} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)


### POST/create
Per l'serimento di un nuovo operatore R.A.O.

Input (form-data): 
*	username [type:string] (Codice fiscale nuovo operatore)
*	entity [type:string] (Codice IPA)


Output:
*	JSON {‘statusCode’: 200, ‘message’: ‘124578’} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)


### POST/activate
Per l'attivazione di un nuovo operatore.

Input (form-data): 
*	new_pin [type:string] (Nuovo PIN dell'operatore)
*	entity [type:string] (Codice IPA)
*	(se ADMIN) cert [type:string] (certificato .pem)


Output:
*	JSON {‘statusCode’: 200, ‘message’: ‘Operatore attivato con successo.’} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)


### POST/sign
Per firmare le richieste di identificazione SPID.

Input (form-data): 
*	payload [type:string] (JSON della richiesta da firmare)
*	entity [type:string] (Codice IPA)


Output:
*	JSON {‘statusCode’: 200, ‘cert’: *campo usato per la creazione del JWT*, 'alg': *campo alg dell'header del JWT*, 'sign': *campo x5c dell'header del JWT*} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)


### POST/reset_pin
Per generare un pin temporaneo da assegnare ad un operatore (da modificare al primo accesso).

Input (form-data): 
*	username [type:string] (Codice fiscale operatore)
*	entity [type:string] (Codice IPA)


Output:
*	JSON {‘statusCode’: 200, ‘message’: ‘Operazione eseguita correttamente.’} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)
	

### POST/deactivate
Per disabilitare un operatore attivo.

Input (form-data): 
*	username [type:string] (Codice fiscale operatore)
*	entity [type:string] (Codice IPA)


Output:
*	JSON {‘statusCode’: 200, ‘message’: ‘Operazione eseguita correttamente.’} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)


### POST/update_cert
Per caricare il nuovo certificato da utilizzare per la firma dei token.

Input (form-data): 
*	cert [type:string] (certificato .pem)
*	entity [type:string] (Codice IPA)


Output:
*	JSON {‘statusCode’: 200, ‘message’: ‘Operazione eseguita correttamente.’} (es. success)
*	JSON {‘statusCode’: 400, ‘message’: ‘Richiesta errata’} (es. error)
