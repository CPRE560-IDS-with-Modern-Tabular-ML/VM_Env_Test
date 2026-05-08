# First, after crerating the env "cpre560" you must install this:
conda install ipykernel

# And register the kernel as well (in the conda env)
python -m ipykernel install --user --name cpre560 --display-name "Python (cpre560)"

# Install all the libraries for the infernece notebook with this one-liner:
pip install xgboost pandas numpy matplotlib seaborn scikit-learn ipython
