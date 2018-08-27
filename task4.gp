/**********************************
 primes generation 
***********************************/
randbBits(b)={ 
    local(x);
    x = random(2^(b-1)) + 2^(b-1);
    return(x);
}  

    randPrime(b)={ 
    local(x);
    if(b<3,
        print(" generating prime")
    ,/*ELSE*/
        x = randbBits(b);
        while( x<=5 || isprime(x)!=1 , x=randbBits(b));
        return(x);
    )
}

randcoprime(N)={
    local(k);
    k = random(N);
    while(gcd(k,N)!=1 , k = random(N));
    return(k);
}

/**********************************
 RSA primes generation 
***********************************/
\\ naive generation of RSA primes, applying the definition
randRSAprime(b)={
    local(x);
    if(b<3,
        print("an RSA prime should be greater than 5, then b should be greater than 2")
    , /* ELSE */
        x = randPrime(b);
        while( x<5 && isprime((x-1)/2)!=1 , x=randPrime(b));
    );
    return(x);
} 

\\optimized generation, minimizing operations and using fast algorithms for primality
getRSAprime(b)={
    local(p,q,r);
    while(1,
        p = 2^(b-1)+random(2^(b-1));
        if(ispseudoprime(p),	
            q = (p-1)/2;
            if(isprime(q),
                if(isprime(p),
                    return(p);
                );
            );
        );
    );
}

\\ naive generation of RSA strong primes, applying the definition
randRSAStrongPrime(b)={
    local(x);
    if(b<3,print("an RSA prime should be greater than 5, then b should be greater than 2")
    , /* ELSE */
        x = randPrime(b);
        while( isRSAprime((x-1)/2)!=1 , x=randPrime(b));
    );
    return(x);
} 

\\optimized generation, minimizing operations and using fast algorithms for primality
getStrongRSAprime(b)={
    local(p,q,r);
    while(1,
        p=2^(b-1)+random(2^(b-1));
        if(ispseudoprime(p),	
            q=(p-1)/2;
            if(isprime(q),
                r=(q-1)/2;
                if(isprime(r),
                    if(isprime(p),
                        return(p);
                    );
                );
            );
        );
    );
}


/*** primes generation for DSS signature ***/
randPrimeDSS(pbitlength,qbitlength)=
{
    local(q,temp,abitlength,a,p);
    q = randPrime(qbitlength);
    temp = 2*q;
    abitlength = pbitlength - qbitlength - 1;
    a = randbBits(abitlength);
    p = temp*a;
    while(isprime(p)==0,
        p = p+temp;
        a++;
    );
    return([p,q,a]);
}

genRSAKeys(b,N,p,q,e)=  
{
    local(d,Phi);
    if(N==0,
        p = getStrongRSAprime(b);
        q = getStrongRSAprime(b);
        N = p*q;
    );
    Phi = (p-1)*(q-1);
    if(e == 0,
        e = randcoprime(Phi)
    );
    d = bezout(e,Phi)[1];
    d = lift(Mod(d,Phi));
    return([N,p,q,e,d,Phi]);
} 


/**********************************
Main part
***********************************/

local (p,g,q,e,a,b,c,A,B,C);
p=getRSAprime(16);
print("\n\n\n Result of 4.1: ");
print("\nsafe prime (16 bit) p= ", p);
g=lift(znprimroot(p));
print("\nbase g=", g);
print("\n\n\n Result of 4.2: ");
a=getRSAprime(16);
b=getRSAprime(16);
c=getRSAprime(16);
print("\nPrivate key Alice= ", a);
print("\nPrivate key Bob= ", b);
print("\nPrivate key Eve= ", c);
A=lift(Mod(g^a,p));
B=lift(Mod(g^b,p));
C=lift(Mod(g^c,p));
print("\nPublic key Alice=", A);
print("\nPublic key Bob=", B);
print("\nPublic key Eve=", C);

print("\n\n\n Result of 4.3: ");
print("We have p=",p," and g=",g);
print("\nPublic key Alice=", A," sent to Bob");
print("\nPublic key Bob=", B, " sent to Alice");
print("\nAlice calculated secret key=",lift(Mod(B^a,p)));
print("\nAlice calculated secret key=",lift(Mod(A^b,p)));

print("\nKeys are same!");

print("\n\n\n Result of 4.4: ");
print("We have p=",p," and g=",g);
print("\nPublic key Alice=", A," sent to Bob");
print("\nBut.. Eve modified that and sent to Bob her own=",C);
print("\nPublic key Bob=", B, " sent to Alice");
print("\nBut.. Eve modified that and sent to Alice her own=",C);
print("\n\nEva calculated secret key to communicate with Alice=",lift(Mod(A^c,p)));
print("\nAlice calculated secret key=",lift(Mod(C^a,p)));

print("\n\nEva calculated secret key to communicate with Bob=",lift(Mod(B^c,p)));
print("\nBob calculated secret key=",lift(Mod(C^b,p)));

print("\nall communications between Alice and Bob goes through Eva");










