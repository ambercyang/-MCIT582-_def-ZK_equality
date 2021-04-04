#!/usr/bin/env python
# coding: utf-8

# In[ ]:


#pip install git+https://github.com/spring-epfl/zksk


# In[1]:


from zksk import Secret, DLRep
from zksk import utils


# In[54]:


def ZK_equality(G,H):

##Generate two El-Gamal ciphertexts (C1,C2) and (D1,D2)
    # Setup: generate secret randomizers.    
    # m is the secret bit.
    m = Secret(utils.get_random_num(bits=2))
    r1 = Secret(utils.get_random_num(bits=128))
    r2 = Secret(utils.get_random_num(bits=128))

    C1 = r1.value*G
    #print("this is C1:", C1)
    C2 = r1.value * H + m.value * G
    D1 = r2.value * G
    D2 = r2.value * H + m.value * G
    
##Generate a NIZK proving equality of the plaintexts 

    stmt = DLRep(C1,r1*G) & DLRep(C2,r1*H+m*G) & DLRep(D1,r2*G) & DLRep(D2,r2*H+m*G)
    zk_proof = stmt.prove()
    
    #Return two ciphertexts and the proof
    return (C1,C2), (D1,D2), zk_proof


# In[53]:


#G, H = utils.make_generators(num=2, seed=42)
#print("this is G, H", G," ,",H)


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:




