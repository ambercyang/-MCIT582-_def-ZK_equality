#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#pip install git+https://github.com/spring-epfl/zksk


# In[1]:


from zksk import Secret, DLRep
from zksk import utils


# In[3]:


def ZK_equality(G,H):

##Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    # Setup: generate a secret randomizer.
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))
    C1 = r1.value * G
    C2 = r2.value * G
  
    
    # This is Peggy's secret bit.
    top_secret_bit = 1
    

    # A Pedersen commitment to the secret bit.
    D1 = top_secret_bit * G + r1.value * H
    D2 = top_secret_bit * G + r2.value * H
    
    
##Generate a NIZK proving equality of the plaintexts     
    stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G)
    zk_proof = stmt.prove()
    
    
    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof


# In[ ]:




