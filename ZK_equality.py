#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#pip install git+https://github.com/spring-epfl/zksk


# In[1]:


from zksk import Secret, DLRep
from zksk import utils


# In[2]:


def ZK_equality(G,H):

##Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    # Setup: generate a secret randomizer.
    
    # M is the secret bit.
    #m = 1
    m = Secret(utils.get_random_num(bits=128))
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))
    #print("this is r1 and r2:", r1.value,",",r2.value)
    C1 = r1* G
    #C2 = m * G + r1.value * H
    D1 = r2 * G
    #D2 = m * G + r2.value * H
    #C1 = r1 * G
    C2 = m * G + r1* H
    #D1 = r2 * G
    D2 = m * G + r2* H    
  

    # A Pedersen commitment to the secret bit.   
    
##Generate a NIZK proving equality of the plaintexts 
    #print("this is DLRep(C1,r1*G):", DLRep(C1,r1*G))
    stmt = DLRep(C1,r1*G) & DLRep(C2,m*G+r1*H) & DLRep(D1,r2*G) & DLRep(D2,m*G+r2*H)
    zk_proof = stmt.prove()
    
    
    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof


# In[3]:


G, H = utils.make_generators(num=2, seed=42)


# In[4]:


ZK_equality(G,H)


# In[ ]:




