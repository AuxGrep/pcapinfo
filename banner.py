import time
import os


class banner():
    frames = [
        '''
    __  __    _    _ __        ___    ____  _____ 
    |  \/  |  / \  | |\ \      / / \  |  _ \| ____|
    | |\/| | / _ \ | | \ \ /\ / / _ \ | |_) |  _|  
    | |  | |/ ___ \| |__\ V  V / ___ \|  _ <| |___ 
    |_|  |_/_/   \_\_____\_/\_/_/   \_\_| \_\_____|
        
        ''',
        '''
    ____   ____    _    ____      ___ _   _ _____ ___  
    |  _ \ / ___|  / \  |  _ \    |_ _| \ | |  ___/ _ \ 
    | |_) | |     / _ \ | |_) |____| ||  \| | |_ | | | |
    |  __/| |___ / ___ \|  __/_____| || |\  |  _|| |_| |
    |_|    \____/_/   \_\_|       |___|_| \_|_|   \___/ 

                                Coded By AuxGrep
                                                
        ''',
        '''
    ____   ____    _    ____      ___ _   _ _____ ___  
    |  _ \ / ___|  / \  |  _ \    |_ _| \ | |  ___/ _ \ 
    | |_) | |     / _ \ | |_) |____| ||  \| | |_ | | | |
    |  __/| |___ / ___ \|  __/_____| || |\  |  _|| |_| |
    |_|    \____/_/   \_\_|       |___|_| \_|_|   \___/ 
                            
        ''',
        '''
    ____   ____    _    ____      ___ _   _ _____ ___  
    |  _ \ / ___|  / \  |  _ \    |_ _| \ | |  ___/ _ \ 
    | |_) | |     / _ \ | |_) |____| ||  \| | |_ | | | |
    |  __/| |___ / ___ \|  __/_____| || |\  |  _|| |_| |
    |_|    \____/_/   \_\_|       |___|_| \_|_|   \___/ 
                            
        '''
    ]

    for i in range(10):
        # Clear the console
        print("\033c", end="")
        
        # Get the current frame and print it
        current_frame = frames[i % len(frames)]
        print(current_frame)
        
        # Wait for 0.2 seconds
        time.sleep(0.2)
        os.system('clear')
