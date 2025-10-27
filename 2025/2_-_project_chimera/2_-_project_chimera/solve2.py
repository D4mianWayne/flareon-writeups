import os
import sys
import emoji
import random
import cowsay
import pyjokes
import art
from arc4 import ARC4

# Catalyst activation function
def activate_catalyst():
    LEAD_RESEARCHER_SIGNATURE = b'm\x1b@I\x1dAoe@\x07ZF[BL\rN\n\x0cS'
    ENCRYPTED_CHIMERA_FORMULA = b'r2b-\r\x9e\xf2\x1fp\x185\x82\xcf\xfc\x90\x14\xf1O\xad#]\xf3\xe2\xc0L\xd0\xc1e\x0c\xea\xec\xae\x11b\xa7\x8c\xaa!\xa1\x9d\xc2\x90'

    print('--- Catalyst Serum Injected ---')
    print("Verifying Lead Researcher's credentials via biometric scan...")

    current_user = b"G0ld3n_Tr4nsmut4t10n"

    # Generate a simple user signature by XORing each character with its index + 42
    user_signature = bytes(c ^ (i + 42) for i, c in enumerate(current_user))

    status = 'pending'

    if status == 'pending':
        if user_signature == LEAD_RESEARCHER_SIGNATURE:
            art.tprint('AUTHENTICATION   SUCCESS', font='small')
            print('Biometric scan MATCH. Identity confirmed as Lead Researcher.')
            print('Finalizing Project Chimera...')

            # Decrypt the secret formula using ARC4
            arc4_decipher = ARC4(current_user)
            decrypted_formula = arc4_decipher.decrypt(ENCRYPTED_CHIMERA_FORMULA).decode()

            # Announce the decrypted formula using cowsay
            cowsay.cow('I am alive! The secret formula is:\n' + decrypted_formula)
            return
        else:
            art.tprint('AUTHENTICATION   FAILED', font='small')
            print('Impostor detected, my genius cannot be replicated!')
            print('The resulting specimen has developed an unexpected, and frankly useless, sense of humor.')

            # Tell a random joke using cowsay
            joke = pyjokes.get_joke(language='en', category='all')
            animals = cowsay.char_names[1:]  # Exclude the first character
            cowsay_output = cowsay.get_output_string(random.choice(animals), joke)
            print(cowsay_output)

            sys.exit(1)

    print('System error: Unknown experimental state.')


# Run the catalyst activation
activate_catalyst()
