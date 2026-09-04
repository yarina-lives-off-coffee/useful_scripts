#!/bin/bash

# automated VM deployment

# config variables
RESOURCE_GROUP="rg-vm-lab"
LOCATION="westeurope"
VM_SIZES=(
    "Standard_B1s"
    "Standard_B2s"
    "Standard_B2ms"
)
# base name for the VMs
VM_PREFIX="lab-vm"

echo "Creating resource group: $RESOURCE_GROUP"
az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION"

# deploy VMs
echo "Starting VM deployment..."
VM_LIST=()
for i in "${!VM_SIZES[@]}"; do
    VM_NAME="${VM_PREFIX}-$((i + 1))"
    VM_SIZE="${VM_SIZES[$i]}"
    echo "Creating VM: $VM_NAME"
    echo "Size: $VM_SIZE"
    az vm create \
        --resource-group "$RESOURCE_GROUP" \
        --name "$VM_NAME" \
        --image "Ubuntu2204" \
        --size "$VM_SIZE" \
        --admin-username "azureadmin" \
        --generate-ssh-keys
    # add VM to list
    VM_LIST+=("$VM_NAME")

done

# display deployed VMs
echo "Successfully deployed VMs:"
for VM in "${VM_LIST[@]}"; do
    echo "- $VM"
done

echo ""
echo "Deployment completed."
